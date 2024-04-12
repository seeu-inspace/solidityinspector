#!/usr/bin/env ruby

require 'find'
require 'json'



def logo
	result = ""
	lines = [ " __                     ___       _",
			  "(_  _  |  o  _| o _|_ \\/ | __  _ |_) _  _ _|_ _  __",
			  "__)(_) |  | (_| |  |_ \/ _|_| |_> |  (\/_(_  |_(_) |"
	]

	lines.each do |line|
		line.each_char.with_index do |char, i|
			shade = (i / 8) % 8 + 81
			result += "\e[38;5;#{shade}m#{char}\e[0m"
		end
		result += "\n"
	end

	result
	puts result
	
	chars = "└───────■ Made with <3 by Riccardo Malatesta (@seeu)".chars
	chars.each_with_index do |char, index|
		shade = (index / 8) % 8 + 81
		print "\e[38;5;#{shade}m#{char}\e[0m"
		sleep(0.01) 
	end
	
	puts "\n\n"
	
end



def is_comment?(line)
	line_check = line.gsub(/[ \t]/, '')
	line_check.match?(/\A\s*(\/\/|\/\*|\*)|\*\/\s*\z/)
end



def extract_pragma_version(solidity_file)
	pragma_line = solidity_file.split("\n").find { |line| line.start_with?("pragma solidity") }
	if pragma_line != nil
		pragma_line.match(/pragma solidity (.*?);/)[1]
	else
		"no_version_found"
	end
end



# ToDo: a version of this function to checks for versions in `Makefile`
def check_dependencies_issues(dependencies, issues_map)
	if dependencies
		if dependencies['@openzeppelin/contracts']
			openzeppelin_version = dependencies['@openzeppelin/contracts']
			major, minor, patch = openzeppelin_version.gsub(/[\^<>!=]/, '').split(".")
			if major.to_i < 4 || (major.to_i == 4 && (minor.to_i < 9 || (minor.to_i == 9 && patch.to_i < 5)))
				issues_map << {key: :outdated_openzeppelin_contracts, title: "\e[31mOutdated version of openzeppelin-contracts\e[0m", description: "Implementing an outdated version of `@openzeppelin/contracts`, specifically prior to version 4.9.5, introduces multiple high severity issues into the protocol's smart contracts, posing significant security risks. Immediate updating is crucial to mitigate vulnerabilities and uphold the integrity and trustworthiness of the protocol's operations. [Check openzeppelin-contracts public reported and fixed security issues](https://github.com/OpenZeppelin/openzeppelin-contracts/security).", issues: "\n::package.json => Version of @openzeppelin/contracts is #{openzeppelin_version}"}
			end
		end

		if dependencies['@openzeppelin/contracts-upgradeable']
			openzeppelin_version = dependencies['@openzeppelin/contracts-upgradeable']
			major, minor, patch = openzeppelin_version.gsub(/[\^<>!=]/, '').split(".")
			if major.to_i < 4 || (major.to_i == 4 && (minor.to_i < 9 || (minor.to_i == 9 && patch.to_i < 5)))
				issues_map << {key: :outdated_openzeppelin_contracts_upgradeable, title: "\e[31mOutdated version of openzeppelin-contracts-upgradeable\e[0m", description: "Implementing an outdated version of `@openzeppelin/contracts-upgradeable`, specifically prior to version 4.9.5, introduces multiple high severity issues into the protocol's smart contracts, posing significant security risks. Immediate updating is crucial to mitigate vulnerabilities and uphold the integrity and trustworthiness of the protocol's operations. [Check openzeppelin-contracts public reported and fixed security issues](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/security).", issues: "\n::package.json => Version of @openzeppelin/contracts-upgradeable is #{openzeppelin_version}"}
			end
		end
	end
end



def check_openzeppelin_version(directory, issues_map)

	package_json_path = File.join(directory, 'package.json')

	if File.exist?(package_json_path)

		package_json = JSON.parse(File.read(package_json_path))

		check_dependencies_issues(package_json['devDependencies'], issues_map)
		check_dependencies_issues(package_json['dependencies'], issues_map)

	end

end



def check_for_issues(solidity_file)
	issues = {}

	inside_loop = false

	pragma_version = extract_pragma_version(solidity_file)

	major, minor, patch = pragma_version.gsub(/[\^<>!=]/, '').split(".")

	#gas issues
	issues[:use_recent_solidity] = issues[:use_recent_solidity].to_s + "\n => pragma solidity " + pragma_version + ";" if (minor.to_i < 8 || ( minor.to_i == 8 && patch.to_i < 10)) && pragma_version != "no_version_found"

	# qa issues
	# :: non-critical issues ::
	issues[:missing_spdx] = " => The Solidity file is missing the SPDX-License-Identifier" if !solidity_file.include?("SPDX-License-Identifier")
	# :: low issues ::
	issues[:unspecific_compiler_version_pragma] = " => pragma solidity " + pragma_version + ";" if pragma_version.include?("<") || pragma_version.include?(">") || pragma_version.include?(">=") || pragma_version.include?("<=") || pragma_version.include?("^")
	issues[:outdated_pragma] = issues[:outdated_pragma].to_s + " => #{pragma_version}" if (minor.to_i < 8 || ( minor.to_i == 8 && patch.to_i < 10)) && pragma_version != "no_version_found"
	issues[:push_0_pragma] = issues[:push_0_pragma].to_s + " => #{pragma_version}" if (minor.to_i > 8 || ( minor.to_i == 8 && patch.to_i > 19)) && pragma_version != "no_version_found"


	lines = solidity_file.split("\n")

	lines.each_with_index do |line, index|

		# template to add an issue:		issues[:KEY] = issues[:KEY].to_s + format if CONDITION
		format = "\n::#{index + 1} => #{line}"

		issues[:todo_unfinished_code] = issues[:todo_unfinished_code].to_s + format if line =~ /todo|to do/i

		next if is_comment?(line)

		if (line.include?("for") || line.include?("while")) && line.include?("{")
			inside_loop = true
		end

		# gas issues
		issues[:bool_storage_overhead] = issues[:bool_storage_overhead].to_s + format if line.match?(/(bool.[a-z,A-Z,0-9]*.?=.?)|(bool.[a-z,A-Z,0-9]*.?;)|(=> bool)/) && !line.include?("function") && !line.include?("event")
		issues[:cache_array_outside_loop] = issues[:cache_array_outside_loop].to_s + format if ( line.include?(".length") || line.include?(".size") ) && ( line.include?("while") || line.include?("for") )
		issues[:default_variable_initialization] = issues[:default_variable_initialization].to_s + format if line.match?(/(uint[0-9]*[[:blank:]][a-z,A-Z,0-9]*.?=.?0;)|(bool.[a-z,A-Z,0-9]*.?=.?false;)/) || line.match?(/.?=.?0;/) && line.start_with?(/uint[0-9]*[[:blank:]][a-z,A-Z,0-9]/)
		issues[:shift_instead_of_divmul] = issues[:shift_instead_of_divmul].to_s + format if line.match?(/\/[2,4,8]|\/ [2,4,8]|\*[2,4,8]|\* [2,4,8]/)
		issues[:use_diff_from_0] = issues[:use_diff_from_0].to_s + format if line.match?(/>0|> 0/)
		issues[:long_revert_string] = issues[:long_revert_string].to_s + format if line =~ /'[\w\d\s]{33,}'/ || line =~ /"[\w\d\s]{33,}"/
		issues[:postfix_increment] = issues[:postfix_increment].to_s + format if line.include?("++") || line.include?("--")
		issues[:non_constant_or_immutable_variables] = issues[:non_constant_or_immutable_variables].to_s + format if (line.match?(/(uint[0-9]*[[:blank:]][a-z,A-Z,0-9]*.?=.?;)|(bool.[a-z,A-Z,0-9]*.?=.?;)/) || line.match?(/.?=.?;/) && line.start_with?(/uint[0-9]*[[:blank:]][a-z,A-Z,0-9]/)) && !line.match?(/immutable|constant/) && !line.include?("function")
		issues[:public_function] = issues[:public_function].to_s + format if line.include?("function") && line.include?("public") && (minor.to_i < 6 || ( minor.to_i == 6 && patch.to_i < 9)) && pragma_version != "no_version_found"
		issues[:revert_function_not_payable] = issues[:revert_function_not_payable].to_s + format if (line.match?(/only/) && line.include?("function") && (line.include?("external") || line.include?("public"))) && !line.include?("payable")
		issues[:assembly_address_zero] = issues[:assembly_address_zero].to_s + format if line.include?("address(0)")
		issues[:assert_instead_of_require] = issues[:assert_instead_of_require].to_s + format if line.include?("assert(")
		issues[:small_uints] = issues[:small_uints].to_s + format if line.match?(/\buint(\d{1,2})\b|\bint(\d{1,2})\b/) && ($1.to_i < 32 || $2.to_i < 32) && line.include?("=")
		issues[:use_selfbalance] = issues[:use_selfbalance].to_s + format if line.include?("address(this).balance")
		issues[:use_immutable] = issues[:use_immutable].to_s + format if line.include?("keccak256(") && line.include?("constant") && (minor.to_i < 6 || ( minor.to_i == 6 && patch.to_i < 12)) && pragma_version != "no_version_found"
		issues[:use_require_andand] = issues[:use_require_andand].to_s + format if line.include?("require(") && line.include?("&&")
		issues[:math_gas_cost] = issues[:math_gas_cost].to_s + format if line.include?("-=") || line.include?("+=")
		issues[:postfix_increment_unchecked] = issues[:postfix_increment_unchecked].to_s + format if (line.include?("++") || line.include?("--")) && !line.include?("unchecked{") && (minor.to_i > 8 || ( minor.to_i == 8 && patch.to_i >= 0)) && (line.include?("while") || line.include?("for")) && pragma_version != "no_version_found"
		issues[:superfluous_event_fields] = issues[:superfluous_event_fields].to_s + format if (line.match?(/timestamp/) || line.include?("block.timestamp") || line.include?("block.number")) && line.include?("event")
		issues[:bool_equals_bool] = issues[:bool_equals_bool].to_s + format if line.include?("==") && (line.include?("false") || line.include?("true"))
		issues[:strict_comparison] = issues[:strict_comparison].to_s + format if (line.include?(">") || line.include?("<")) && !line.include?("=")
		issues[:private_rather_than_public] = issues[:private_rather_than_public].to_s + format if line.match?(/(public.?constant.?|constant.?public.?)[^=\n\(]*(=|;)/i)

		# qa issues
		# :: non-critical issues ::
		issues[:require_revert_missing_descr] = issues[:require_revert_missing_descr].to_s + format if line.match?(/require\(|revert\(/) && !line.include?("\"")
		issues[:unnamed_return_params] = issues[:unnamed_return_params].to_s + format if line.include?("function") && line.include?("returns") && !line.end_with?(";")
		issues[:use_of_abi_encodepacked] = issues[:use_of_abi_encodepacked].to_s + format if line.match?(/abi.encodePacked\(/) && (minor.to_i > 8 || (minor.to_i == 8 && patch.to_i >= 4)) && pragma_version != "no_version_found"
		issues[:make_modern_import] = issues[:make_modern_import].to_s + format if line.include?("import") && !line.include?("{")
		issues[:file_missing_pragma] = issues[:file_missing_pragma].to_s + " => no_version_found" if pragma_version == "no_version_found"
		issues[:magic_numbers] = issues[:magic_numbers].to_s + format if (line.match?(/\b\d{2,}\b/) || line.match?(/-?\d\.?\d*[Ee][+\-]?\d+/) || line.match?(/\b\d{1,3}(?:_\d{3})+\b/)) && !line.include?("pragma") && !line.include?("int")
		## => public_func_not_used_internally
		if line.include?("function") && line.include?("public")
			function_name = line.match(/function\s+(\w+)\s*\(/)&.captures&.first
			if function_name
				# Count the occurrences of the function name in the contract
				function_usage_count = lines.count { |l| l.include?(function_name) }
				if function_usage_count == 1
					issues[:public_func_not_used_internally] = issues[:public_func_not_used_internally].to_s + format
				end
			end
		end
		# :: low issues ::
		issues[:empty_body] = issues[:empty_body].to_s + format if line.match?(/(\{\})|(\{ \})/i) && !line.include?("//") && !line.include?("receive()")
		issues[:unsafe_erc20_operations] = issues[:unsafe_erc20_operations].to_s + format if line.match?(/\.transferFrom\(|\.increaseAllowance\(|\.decreaseAllowance\(/)
		issues[:deprecated_oz_library_functions] = issues[:deprecated_oz_library_functions].to_s + format if line.match?(/_setupRole\(|safeApprove\(|tokensOf\(/)		
		issues[:abiencoded_dynamic] = issues[:abiencoded_dynamic].to_s + format if line.include?("abi.encodePacked(") && line.include?("keccak256(")
		issues[:transfer_ownership] = issues[:transfer_ownership].to_s + format if line.match?(/\.transferOwnership\(/)
		issues[:use_safemint] = issues[:use_safemint].to_s + format if line.match?(/_mint\(/)
		issues[:draft_openzeppelin] = issues[:draft_openzeppelin].to_s + format if line.include?("import") && line.include?("openzeppelin") && line.include?("draft")
		issues[:use_of_blocktimestamp] = issues[:use_of_blocktimestamp].to_s + format if line.include?("block.timestamp") || line.include?("now")
		issues[:calls_in_loop] = issues[:calls_in_loop].to_s + format if line.match?(/\.transfer\(|\.transferFrom\(|\.call|\.delegatecall/) && inside_loop
		issues[:ownableupgradeable] = issues[:ownableupgradeable].to_s + format if line.include?("OwnableUpgradeable")
		issues[:ecrecover_addr_zero] = issues[:ecrecover_addr_zero].to_s + format if line.include?("ecrecover(") && !line.include?("address(0)")
		issues[:dont_use_assert] = issues[:dont_use_assert].to_s + format if line.include?("assert(")
		issues[:deprecated_cl_library_function] = issues[:dont_use_assert].to_s + format if line.match?(/\.getTimestamp\(|\.getAnswer\(|\.latestRound\(|\.latestTimestamp\(/)

		# medium issues
		issues[:single_point_of_control] = issues[:single_point_of_control].to_s + format if line.match(/( onlyOwner )|( onlyRole\()|( requiresAuth )|(Owned)!?([(, ])|(Ownable)!?([(, ])|(Ownable2Step)!?([(, ])|(AccessControl)!?([(, ])|(AccessControlCrossChain)!?([(, ])|(AccessControlEnumerable)!?([(, ])|(Auth)!?([(, ])|(RolesAuthority)!?([(, ])|(MultiRolesAuthority)!?([(, ])/i)
		issues[:use_safemint_msgsender] = issues[:use_safemint_msgsender].to_s + format if line.match?(/_mint\(/) && line.include?("msg.sender")
		issues[:use_of_cl_lastanswer] = issues[:use_of_cl_lastanswer].to_s + format if line.match?(/\.latestAnswer\(/)
		issues[:solmate_not_safe] = issues[:solmate_not_safe].to_s + format if line.match?(/\.safeTransferFrom\(|.safeTransfer\(|\.safeApprove\(/) if solidity_file.include?("SafeTransferLib.sol")

		# high issues
		issues[:delegatecall_in_loop] = issues[:delegatecall_in_loop].to_s + format if line.match?(/\.delegatecall\(/) && inside_loop
		## arbitrary_from_in_transferFrom
		if line.match?(/\btransferFrom\s*\(/) || line.match?(/\bsafeTransferFrom\s*\(/)
			# Extracting the first argument within parentheses
			first_arg = line.match(/\b(?:transferFrom|safeTransferFrom)\s*\(\s*([^\s,]+)/)&.captures&.first
			if first_arg && first_arg != "msg.sender"
				issues[:arbitrary_from_in_transferFrom] = issues[:arbitrary_from_in_transferFrom].to_s + format
			end
		end

		# check if you are not in a loop anymore
		if line.include?("}") && inside_loop
			inside_loop = false
		end

	end

	issues

end



def create_report(issues_map, sol_files)

	# --- PREPARE THE CONTENT OF THE REPORT ---

	# Define categories of issues
	categories = {
		high: "High Issues",
		medium: "Medium Issues",
		low: "Low Issues",
		non_critical: "Non-Critical Issues",
		gas: "Gas Issues"
	}

	# Initialize categories
	categorized_issues = Hash.new(0)

	# Count issues for each category
	issues_map.each do |issue_map|
		next if issue_map[:issues].empty?

		category = :general # Default category if not matched

		if issue_map[:title].include?("\e[37m")
			category = :gas
		elsif issue_map[:title].include?("\e[92m")
			category = :non_critical
		elsif issue_map[:title].include?("\e[32m")
			category = :low
		elsif issue_map[:title].include?("\e[33m")
			category = :medium
		elsif issue_map[:title].include?("\e[31m")
			category = :high
		end

		categorized_issues[category] += 1
	end

	# Initialize categories
	categorized_issues = Hash.new { |hash, key| hash[key] = [] }

	# Initialize counters for each severity category
	severity_counters = {
		gas: 0,
		non_critical: 0,
		low: 0,
		medium: 0,
		high: 0
	}

	# Categorize issues
	issues_map.each do |issue_map|
		next if issue_map[:issues].empty? # Skip if issues are empty

		category = :general # Default category if not matched
		severity = nil

		if issue_map[:title].include?("\e[37m")
			category = :gas
			severity = "G"
		elsif issue_map[:title].include?("\e[92m")
			category = :non_critical
			severity = "NC"
		elsif issue_map[:title].include?("\e[32m")
			category = :low
			severity = "L"
		elsif issue_map[:title].include?("\e[33m")
			category = :medium
			severity = "M"
		elsif issue_map[:title].include?("\e[31m")
			category = :high
			severity = "H"
		end

		# Increment the severity counter for the current category
		severity_counters[category] += 1

		# Add issue to the categorized list
		categorized_issues[category] << {
			issue: issue_map,
			severity: severity,
			position: severity_counters[category]
		}
	end

	# Sort issues within each category by severity
	categorized_issues.each do |category, issues|
		categorized_issues[category] = issues.sort_by { |item| [item[:severity], item[:position]] }
	end


	### --- CREATE THE REPORT .md FILE ---

	report_file = File.open("solidityinspector_report.md", "w")

	report_file.puts "# SolidityInspector Analysis Report\n\n"

	report_file.puts "This report was generated by [SolidityInspector](https://github.com/seeu-inspace/solidityinspector) a tool made by [Riccardo Malatesta (@seeu)](https://riccardomalatesta.com/). The purpose of this report is to assist in the process of identifying potential security weaknesses and should not be relied upon for any other use.\n\n"


	# Write Table of Contents
	report_file.puts "## Table of Contents\n\n"
	report_file.puts "- [Summary](#summary)\n\t- [Files analyzed](#files-analyzed)\n\t- [Issues found](#issues-found)"

	categories.keys.each do |category|
		if categorized_issues[category].any?
		report_file.puts "- [#{categories[category]}](##{categories[category].downcase.gsub(/\s/, '-')})"
			categorized_issues[category].each do |issue|
				issue_title = issue[:issue][:title].gsub(/\e\[\d+m/, '') # Remove ANSI escape codes
				sanitized_title = issue_title
				  .downcase								   # Convert to lowercase
				  .delete("`!@#\$%^&*()[]{}|\\\":;'<>,.?~\/") # Remove most special characters
				  .gsub(/[^a-z0-9\-]/, '-')				   # Replace non-alphanumeric characters with hyphens
				  .split('-')								 # Split the string by hyphens
				  .reject(&:empty?)						   # Remove empty elements (resulting from consecutive hyphens)
				  .join('-')								  # Join the remaining elements back together with a single hyphen
				report_file.puts "\t- [#{issue[:severity]}-#{'%02d' % issue[:position]} #{issue_title}](##{issue[:severity]}-#{'%02d' % issue[:position]}-#{sanitized_title})"
			end
		end
	end

	report_file.puts "\n"

	# Write "Summary" section
	report_file.puts "## Summary\n\n"

	# Summary -> Write "Files analyzed" table
	report_file.puts "### Files analyzed\n\n"
	report_file.puts "| Filepath |\n| --- |\n"
	sol_files.each do |sol_file|
		report_file.puts "| #{sol_file[:path]} |\n"
	end
	report_file.puts "\n"

	# Summary -> Write "Issues found" table
	report_file.puts "### Issues found\n\n"
	report_file.puts "| Category | Number of issues found |\n| --- | --- |\n"


	# Write counts for each category to the report
	categories.keys.each do |category|
		report_file.puts "| #{categories[category]} | #{severity_counters[category]} |\n" if severity_counters[category] > 0
	end

	report_file.puts "\n"

	# Write categorized issues to the report in the desired order
	categories.keys.each do |category|
		next if categorized_issues[category].empty?

		is_gas = false
		
		if category.to_s == 'gas'
			is_gas = true
		end

		report_file.puts "## #{categories[category]}\n\n"
		
		# Generate the table header 
		
		if is_gas
			report_file.puts "| ID | Issues | Contexts | Instances | Gas Saved |" 
			report_file.puts "|----|--------|----------|-----------|-----------|"
		else 
			report_file.puts "| ID | Issues | Contexts | Instances |"
			report_file.puts "|----|--------|----------|-----------|"
		end


		categorized_issues[category].each do |item|
			issue = item[:issue]
			severity = item[:severity]
			position = item[:position]
			
			contexts_size = issue[:issues].scan(/\.sol/).size || 0
			sanitized_title = issue[:title]
				  .gsub(/\e\[\d+m/, '')						  # Remove ANSI escape codes
				  .downcase								   # Convert to lowercase
				  .delete("`!@#\$%^&*()[]{}|\\\":;'<>,.?~\/") # Remove most special characters
				  .gsub(/[^a-z0-9\-]/, '-')				   # Replace non-alphanumeric characters with hyphens
				  .split('-')								 # Split the string by hyphens
				  .reject(&:empty?)						   # Remove empty elements (resulting from consecutive hyphens)
				  .join('-')								  # Join the remaining elements back together with a single hyphen
			id_link = "[#{severity}-#{'%02d' % position}](##{severity}-#{'%02d' % position}-#{sanitized_title})"
			
			report_file.puts "| #{id_link} | #{issue[:title].gsub(/\e\[\d+m/, '')} | #{contexts_size} | #{issue[:instances]} |" if !is_gas
			report_file.puts "| #{id_link} | #{issue[:title].gsub(/\e\[\d+m/, '')} | #{contexts_size} | #{issue[:instances]} | - | " if is_gas && issue[:gas] == 0
			report_file.puts "| #{id_link} | #{issue[:title].gsub(/\e\[\d+m/, '')} | #{contexts_size} | #{issue[:instances]} | ~#{issue[:gas] * issue[:instances]} | " if is_gas && issue[:gas] > 0

		end

		report_file.puts "\n"
		
		categorized_issues[category].each do |item|
			issue = item[:issue]
			severity = item[:severity]
			position = item[:position]
			
			report_file.puts "### [#{severity}-#{'%02d' % position}] #{issue[:title].gsub(/\e\[\d+m/, '')}\n\n"
			report_file.puts "#{issue[:description]}\n\n"
			if issue[:issues].scan(/::\d{1,3}/).count > 0
				report_file.puts "#### Instances (#{issue[:issues].scan(/::\d{1,3}/).count})\n\n"
			else
				report_file.puts "#### Instances (#{(issue[:issues].scan '=>').count})\n\n"
			end
			
			report_file.puts "```JavaScript#{issue[:issues]}\n```\n\n"
		end

		report_file.puts "\n"
	end

	## EoF
	report_file.close
	puts "\nReport generated: \e[94msolidityinspector_report.md\e[0m"	

end



logo

begin

	current_dir = Dir.pwd

	dir_entries = Dir.entries(current_dir)

	directories = dir_entries.select { |entry| File.directory?(entry) && !['.','..'].include?(entry) }

	puts "Projects in the current directory:"
	directories.each_with_index do |dir, index|
		if index == directories.length - 1
			puts "\e[93m└─\e[0m " + dir
		else
			puts "\e[93m├─\e[0m " + dir
		end
	end
	print "\n"

	print "\e[93m┌─\e[0m Enter a directory:\n\e[93m└─\e[0m "
	directory = gets.chomp

	start_time = Time.now

	if File.exist?(directory) && File.directory?(directory)

		sol_files = []

		Find.find(directory) do |path|
			begin
				sol_files << { path: path, contents: File.read(path) } if File.file?(path) && File.extname(path) == '.sol'
			rescue => e
				puts "\n[\e[31m+\e[0m] ERROR: Error while reading file #{path}: #{e.message}"
			end
		end

		if !sol_files.empty?

			puts "\nFiles analyzed:\n"

			sol_files.each_with_index do |sol_file, index|
				if index == sol_files.length - 1
					puts "\e[93m└─\e[0m " + sol_file[:path]
				else
					puts "\e[93m├─\e[0m " + sol_file[:path]
				end
			end
			print "\n"

			issues_map = []

			# template to add an issue:		issues_map << {key: :KEY, title: "\e[37mTITLE\e[0m", description: "",issues: ""}

			# gas issues
			issues_map << {key: :bool_storage_overhead, title: "\e[37mUsing bools for storage incurs overhead\e[0m", description: "Use uint256 for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from ‘false’ to ‘true’, after having been ‘true’ in the past. This can save 17100 gas per instance. Reference: [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27).", issues: "", gas: 17100}
			issues_map << {key: :cache_array_outside_loop, title: "\e[37mArray length not cached outside of loop\e[0m", description: "Caching the length eliminates the additional `DUP<N>` required to store the stack offset and converts each of them to a `DUP<N>`. Gas saved: 3 per instance. Reference: [[G‑14] `<array>`.length should not be looked up in every loop of a for-loop](https://code4rena.com/reports/2022-12-backed/#g14--arraylength-should-not-be-looked-up-in-every-loop-of-a-for-loop).", issues: "", gas: 3}
			issues_map << {key: :default_variable_initialization, title: "\e[37mVariables initialized with default value\e[0m", description: "When a variable is not set / initialized, it's assumed to have the default value. This means that explicitly initialize a variable with its default value wastes gas. Reference: [Solidity tips and tricks to save gas and reduce bytecode size](https://mudit.blog/solidity-tips-and-tricks-to-save-gas-and-reduce-bytecode-size/).", issues: "", gas: 0}
			issues_map << {key: :shift_instead_of_divmul, title: "\e[37mMissing implementation Shift Right/Left for division and multiplication\e[0m", description: "The `SHR` opcode only utilizes 3 gas, compared to the 5 gas used by the `DIV` opcode. Additionally, shifting is used to get around Solidity's division operation's division-by-0 prohibition. Reference: [EVM Opcodes](https://www.evm.codes/).", issues: "", gas: 2}
			issues_map << {key: :use_diff_from_0, title: "\e[37mUnsigned integer comparison with `> 0`\e[0m", description: "Comparisons done using `!= 0` are cheaper than `> 0` when dealing with unsigned integer types. Reference: [A Collection of Gas Optimisation Tricks - #7 by pcaversaccio](https://forum.openzeppelin.com/t/a-collection-of-gas-optimisation-tricks/19966/7).", issues: "", gas: 0}
			issues_map << {key: :long_revert_string, title: "\e[37mLong `revert`/`require` string\e[0m", description: "Strings in `require()` / `revert()` longer than 32 bytes cost extra gas. Reference: [require() revert() Strings Longer Than 32 Bytes Cost Extra Gas](https://code4rena.com/reports/2022-12-caviar#g-03-requirerevert-strings-longer-than-32-bytes-cost-extra-gas).", issues: "", gas: 0}
			issues_map << {key: :postfix_increment, title: "\e[37mPostfix increment/decrement used\e[0m", description: "The prefix increment / decrease expression returns the updated value after it's incremented while the postfix increment / decrease expression returns the original value. Be careful when employing this optimization anytime the return value of the expression is utilized later; for instance, `uint a = i++` and `uint a = ++i` produce different values for `a`. References: [Why does ++i cost less gas than i++?](https://ethereum.stackexchange.com/questions/133161/why-does-i-cost-less-gas-than-i#answer-133164), [Gas Optimizations for the Rest of Us](https://m1guelpf.blog/d0gBiaUn48Odg8G2rhs3xLIjaL8MfrWReFkjg8TmDoM).", issues: "", gas: 0}
			issues_map << {key: :non_constant_or_immutable_variables, title: "\e[37mVariable not constant/immutable\e[0m", description: "If a variable doesn't need to change, use `constant` or `immutable`. This will avoid the fees due to a `SLOAD` operation. Reference: [Solidity Gas Optimizations pt.2 - Constants](https://dev.to/javier123454321/solidity-gas-optimizations-pt-2-constants-570d).", issues: "", gas: 0}
			issues_map << {key: :public_function, title: "\e[37mMake function external instead of public\e[0m", description: "Version `0.6.9` removed the restriction on public functions accepting calldata arguments. Public functions for Solidity versions `0.6.9` have to transfer the parameters to memory. Reference: [Public vs External Functions in Solidity | Gustavo (Gus) Guimaraes post](https://gus-tavo-guim.medium.com/public-vs-external-functions-in-solidity-b46bcf0ba3ac), [StackOverflow answer](https://ethereum.stackexchange.com/questions/19380/external-vs-public-best-practices?answertab=active#tab-top).", issues: "", gas: 0}
			issues_map << {key: :revert_function_not_payable, title: "\e[37mMark payable functions guaranteed to revert when called by normal users\e[0m", description: "If a normal user tries to pay the function and a function modifier, such as onlyOwner, is applied, the function will revert. By making the function payable, valid callers will avoid paying for gas as the compiler won't verify that a payment was made. The extra opcodes avoided are `CALLVALUE(2)`, `DUP1(3)`, `ISZERO(3)`, `PUSH2(3)`, `JUMPI(10)`, `PUSH1(3)`, `DUP1(3)`, `REVERT(0)`, `JUMPDEST(1)`, `POP(2)` which costs an average of about 21 gas per call to the function, in addition to the extra deployment cost. Reference: [[G‑11] Functions guaranteed to revert when called by normal users can be marked](https://code4rena.com/reports/2022-12-backed/#g11--functions-guaranteed-to-revert-when-called-by-normal-users-can-be-marked-payable).", issues: "", gas: 0}
			issues_map << {key: :assembly_address_zero, title: "\e[37mUse assembly to check for `address(0)`\e[0m", description: "By checking for `address(0)` using assembly language, you can avoid the use of more gas-expensive operations such as calling a smart contract or reading from storage. This can save 6 gas per instance. Reference: [Solidity Assembly: Checking if an Address is 0 (Efficiently)](https://medium.com/@kalexotsu/solidity-assembly-checking-if-an-address-is-0-efficiently-d2bfe071331).", issues: "", gas: 6}
			issues_map << {key: :assert_instead_of_require, title: "\e[37mUse `require` instead of `assert` when possible\e[0m", description: "If `assert()` returns a false assertion, it compiles to the invalid opcode `0xfe`, which eats up all the gas left and completely undoes the changes. `require()` compiles to `0xfd`, which is the opcode for a `REVERT`, indicating that it will return the remaining gas if it returns a false assertion. Reference: [Assert() vs Require() in Solidity – Key Difference & What to Use](https://codedamn.com/news/solidity/assert-vs-require-in-solidity).", issues: "", gas: 0}
			issues_map << {key: :small_uints, title: "\e[37mUsage of uints/ints smaller than 32 bytes (256 bits) incurs overhead\e[0m", description: "Gas consumption can be greater if you use items that are less than 32 bytes in size. This is such that the EVM can only handle 32 bytes at once. In order to increase the element's size from 32 bytes to the necessary amount, the EVM must do extra operations if it is lower than that. When necessary, it is advised to utilize a bigger size and then downcast. References: [Layout of State Variables in Storage | Solidity docs](https://docs.soliditylang.org/en/v0.8.11/internals/layout_in_storage.html#layout-of-state-variables-in-storage), [GAS OPTIMIZATIONS ISSUES by Gokberk Gulgun](https://hackmd.io/@W1m6lTsFT5WAy9C_lRTX_g/rkr5Laoys).", issues: "", gas: 0}
			issues_map << {key: :use_selfbalance, title: "\e[37mUse `selfbalance()` instead of `address(this).balance`\e[0m", description: "The `BALANCE` opcode costs 100 GAS minimum, `SELFBALANCE` costs 5 GAS minimum. References: [BALANCE | EVM Codes](https://www.evm.codes/#31?fork=merge), [SELFBALANCE | EVM Codes](https://www.evm.codes/#47?fork=merge).", issues: "", gas: 0}
			issues_map << {key: :use_immutable, title: "\e[37mUsage of constant keccak variables results in extra hashing\e[0m", description: "The usage of `constant` for keccak variables results in extra hashing and more gas. You should use `immutable`. This saves about 20 gas. References: [Change Constant to Immutable for keccak Variables | Solidity Gas Optimizations Tricks | by Vladislav Yaroshuk | Better Programming](https://betterprogramming.pub/solidity-gas-optimizations-and-tricks-2bcee0f9f1f2#1e4c), [ethereum/solidity#9232 (comment)](https://github.com/ethereum/solidity/issues/9232#issuecomment-646131646), [Inefficient Hash Constants](https://github.com/seen-haus/seen-contracts/issues/29).", issues: "", gas: 20}
			issues_map << {key: :use_require_andand, title: "\e[37mSplit `require()` statements that use `&&` to save gas\e[0m", description: "To save gas, it is advised to use two `require` instead of using one `require` with the operator `&&`. This can save 8 gas per instance. Reference: [How to Write Gas Efficient Contracts in Solidity – Yos Riady](https://yos.io/2021/05/17/gas-efficient-solidity/#tip-11-splitting-require-statements-that-use--saves-gas).", issues: "", gas: 8}
			issues_map << {key: :math_gas_cost, title: "\e[37m`x += y` costs more gas than `x = x + y` for state variables\e[0m", description: "Gas can be saved by substituting the addition operator with plus-equals, same for minus. This can save 10 gas per instance. Reference: [StateVarPlusEqVsEqPlus.md](https://gist.github.com/IllIllI000/cbbfb267425b898e5be734d4008d4fe8).", issues: "", gas: 10}
			issues_map << {key: :postfix_increment_unchecked, title: "\e[37m`++i/i++` should be `unchecked{++i}`/`unchecked{i++}` when it is not possible for them to overflow\e[0m", description: "In solidity versions `0.8.0` and higher, unchecked saves 30-40 gas per loop. Reference: [[G-02] ++i/i++ Should Be unchecked{++i}/unchecked{i++} When It Is Not Possible For Them To Overflow, As Is The Case When Used In For- And While-loops](https://code4rena.com/reports/2022-12-caviar/#g-02-ii-should-be-uncheckediuncheckedi-when-it-is-not-possible-for-them-to-overflow-as-is-the-case-when-used-in-for--and-while-loops).", issues: "", gas: 30}
			issues_map << {key: :superfluous_event_fields, title: "\e[37mSuperfluos event fields\e[0m", description: "In the event information, `block.number` and `block.timestamp` are already added by default. Reference: [[G-08] Superfluous event fields](https://code4rena.com/reports/2022-12-caviar/#g-08-superfluous-event-fields).", issues: "", gas: 0}
			issues_map << {key: :bool_equals_bool, title: "\e[37mUse `if(x)` or `if(!x)` instead of `if (x == bool)`\e[0m", description: "Avoid comparing boolean expressions to boolean literals. This will reduce complexity and gas. Reference: [Don't compare boolean expressions to boolean literals | AuditBase](https://detectors.auditbase.com/boolean-literal-gas-optimization).", issues: "", gas: 0}
			issues_map << {key: :strict_comparison, title: "\e[37mWhen possible, use non-strict comparison `>=` and/or `=<` instead of `>` `<`\e[0m", description: "Non-strict inequalities are cheaper than strict ones due to some supplementary checks (`ISZERO`, 3 gas). It will save 15–20 gas. Reference: [Solidity Gas Optimizations Tricks](https://betterprogramming.pub/solidity-gas-optimizations-and-tricks-2bcee0f9f1f2).", issues: "", gas: 15}
			issues_map << {key: :private_rather_than_public, title: "\e[37mIf possible, use private rather than public for constants\e[0m", description: "If necessary, the values can be obtained from the verified contract source code; alternatively, if there are many values, a single getter function that returns a tuple containing the values of all currently-public constants can be used. The compiler doesn't have to write non-payable getter functions for deployment calldata, store the value's bytes somewhere other than where it will be used, or add another entry to the method ID table. This saves 3406-3606 gas in deployment gas. Reference: [[G‑16] Using private rather than public for constants, saves gas](https://code4rena.com/reports/2022-12-backed/#g16--using-private-rather-than-public-for-constants-saves-gas).", issues: "", gas: 3406}
			issues_map << {key: :use_recent_solidity, title: "\e[37mUse a more recent version of Solidity to save gas\e[0m", description: "Use a version of Solidity at least `0.8.10` to have external calls skip contract existence checks if the external call has a return value (from v `0.8.10`), get custom errors, which are cheaper at deployment than `revert()`/`require()` strings (from v `0.8.4`), get better struct packing and cheaper multiple storage reads (from v `0.8.3`) and get simple compiler automatic inlining (from v `0.8.2`). Reference: [[G-06] Use a more recent version of Solidity](https://code4rena.com/reports/2022-12-backed/#g06--use-a-more-recent-version-of-solidity).", issues: "", gas: 0}

			# qa issues
			# :: non-critical issues ::
			issues_map << {key: :require_revert_missing_descr, title: "\e[92m`require()`/`revert()` statements should have descriptive reason strings\e[0m", description: "To increase overall code clarity and aid in debugging whenever a need is not met, think about adding precise, informative error messages to all `require` and `revert` statements. References: [Error handling: Assert, Require, Revert and Exceptions](https://docs.soliditylang.org/en/v0.8.17/control-structures.html#error-handling-assert-require-revert-and-exceptions), [Missing error messages in require statements | Opyn Bull Strategy Contracts Audit](https://blog.openzeppelin.com/opyn-bull-strategy-contracts-audit/#missing-error-messages-in-require-statements).", issues: ""}
			issues_map << {key: :unnamed_return_params, title: "\e[92mUnnamed return parameters\e[0m", description: "To increase explicitness and readability, take into account introducing and utilizing named return parameters. Reference: [Unnamed return parameters | Opyn Bull Strategy Contracts Audit](https://blog.openzeppelin.com/opyn-bull-strategy-contracts-audit/#unnamed-return-parameters).", issues: ""}
			issues_map << {key: :use_of_abi_encodepacked, title: "\e[92mUsage of `abi.encodePacked` instead of `bytes.concat()` for Solidity version `>= 0.8.4`\e[0m", description: "From the Solidity version `0.8.4` it was added the possibility to use `bytes.concat` with variable number of `bytes` and `bytesNN` arguments. With a more evocative name, it functions as a restricted `abi.encodePacked`. References: [Solidity 0.8.4 Release Announcement](https://blog.soliditylang.org/2021/04/21/solidity-0.8.4-release-announcement/), [Remove abi.encodePacked #11593](https://github.com/ethereum/solidity/issues/11593).", issues: ""}
			issues_map << {key: :make_modern_import, title: "\e[92mFor modern and more readable code; update import usages\e[0m", description: "To be sure to only import what you need, use specific imports using curly brackets. Reference: [[N-03] For modern and more readable code; update import usages | PoolTogether contest](https://code4rena.com/reports/2022-12-pooltogether#n-03-for-modern-and-more-readable-code-update-import-usages).", issues: ""}
			issues_map << {key: :todo_unfinished_code, title: "\e[92mCode base comments with TODOs\e[0m", description: "Consider keeping track of all TODO comments in the backlog of issues and connecting each inline TODO to the related item. Before deploying to a production environment, all TODOs must be completed. Reference: [TODO comments in the code base | zkSync Layer 1 Audit](https://blog.openzeppelin.com/zksync-layer-1-audit/#todo-comments-in-the-code-base).", issues: ""}
			issues_map << {key: :missing_spdx, title: "\e[92m`SPDX-License-Identifier` missing\e[0m", description: "Missing license agreements (`SPDX-License-Identifier`) may result in lawsuits and improper forms of use of code. Reference: [Missing license identifier | UMA DVM 2.0 Audit](https://blog.openzeppelin.com/uma-dvm-2-0-audit/#missing-license-identifier).", issues: ""}
			issues_map << {key: :file_missing_pragma, title: "\e[92mFile is missing pragma\e[0m", description: "Without a pragma statement, the smart contract may encounter compatibility issues with future compiler versions, leading to unpredictable behavior. Reference: [[N‑08] File is missing version pragma | ENS Contest Code4rena](https://code4rena.com/reports/2022-07-ens#n08-file-is-missing-version-pragma).", issues: ""}
			issues_map << {key: :empty_body, title: "\e[92mConsider commenting why the body of the function is empty\e[0m", description: "The functions shown have an empty body. Consider commenting why for a clearer reading of the code. Reference: [[N-12] Empty blocks should be removed or Emit something](https://code4rena.com/reports/2022-11-non-fungible/#n-12-empty-blocks-should-be-removed-or-emit-something).", issues: ""}
			issues_map << {key: :magic_numbers, title: "\e[92mMagic Numbers in contract\e[0m", description: "Magic numbers, undefined numeric literals embedded directly into the code, pose a risk to the readability, maintainability, and security of Solidity smart contracts. To mitigate this issue, establish clear constants or variables for numeric values, providing meaningful context and promoting code transparency. Reference: [Magic numbers are used | Forta Protocol Audit](https://blog.openzeppelin.com/forta-protocol-audit#magic-numbers-are-used).", issues: ""}
			issues_map << {key: :public_func_not_used_internally, title: "\e[92m`public` function not used internally could be marked as `external`\e[0m", description: "`public` functions in a smart contract that aren't actually used within the contract itself could be marked as `external` as they serve no purpose internally.",issues: ""}
			# :: low issues ::
			issues_map << {key: :unspecific_compiler_version_pragma, title: "\e[32mCompiler version Pragma is non-specific\e[0m", description: "For non-library contracts, floating pragmas may be a security risk for application implementations, since a known vulnerable compiler version may accidentally be selected or security tools might fallback to an older compiler version ending up checking a different EVM compilation that is ultimately deployed on the blockchain. References: [Version Pragma | Solidity documents](https://docs.soliditylang.org/en/latest/layout-of-source-files.html#version-pragma), [4.6 Unspecific compiler version pragma | Consensys Audit of 1inch Liquidity Protocol](https://consensys.net/diligence/audits/2020/12/1inch-liquidity-protocol/#unspecific-compiler-version-pragma).", issues: ""}
			issues_map << {key: :unsafe_erc20_operations, title: "\e[32mUnsafe ERC20 operations\e[0m", description: "ERC20 operations might not be secure due to multiple implementations and vulnerabilities in the standard. It is advised to use OpenZeppelin's SafeERC20 or, at least, wrap each operation in a `require` statement. References: [L001 - Unsafe ERC20 Operation(s)](https://github.com/byterocket/c4-common-issues/blob/main/2-Low-Risk.md#l001---unsafe-erc20-operations), [ERC20 OpenZeppelin documentation, contracts/IERC20.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol#L43).", issues: ""}
			issues_map << {key: :deprecated_oz_library_functions, title: "\e[32mDeprecated OpenZeppelin library functions\e[0m", description: "The contracts use deprecated OpenZeppelin Library functions, it is recommend that you avoid using them. References: [openzeppelin-contracts/issues/1064](https://github.com/OpenZeppelin/openzeppelin-contracts/issues/1064), [[L-1] Do not use deprecated library functions](https://gist.github.com/Picodes/ab2df52379e4b4993709be1b91aab651#l-1-do-not-use-deprecated-library-functions).", issues: ""}
			issues_map << {key: :abiencoded_dynamic, title: "\e[32mAvoid using `abi.encodePacked()` with dynamic types when passing the result to a hash function\e[0m", description: "Instead of using `abi.encodePacked()` use `abi.encode()`. It will pad items to 32 bytes, which will prevent [hash collisions](https://docs.soliditylang.org/en/v0.8.13/abi-spec.html#non-standard-packed-mode). It is possible to cast to `bytes()` or `bytes32()` in place of `abi.encodePacked()` when there is just one parameter, see \"[how to compare strings in solidity?](https://ethereum.stackexchange.com/questions/30912/how-to-compare-strings-in-solidity#answer-82739)\". `bytes.concat()` should be used if all parameters are strings or bytes. Reference: [[L-1] abi.encodePacked() should not be used with dynamic types when passing the result to a hash function such as keccak256()](https://gist.github.com/GalloDaSballo/39b929e8bd48704b9d35b448aaa29480#l-1--abiencodepacked-should-not-be-used-with-dynamic-types-when-passing-the-result-to-a-hash-function-such-as-keccak256).", issues: ""}
			issues_map << {key: :transfer_ownership, title: "\e[32mUse `safeTransferOwnership` instead of the `transferOwnership` method\e[0m", description: "`transferOwnership` function is used to change ownership. It is reccomended to use a 2 structure `transferOwnership` which is safer, such as `safeTransferOwnership`. Reference: [[L-02] Use safeTransferOwnership instead of transferOwnership function | Caviar contest](https://code4rena.com/reports/2022-12-caviar/#l-02-use-safetransferownership-instead-of-transferownership-function).", issues: ""}
			issues_map << {key: :use_safemint, title: "\e[32mUse `_safeMint` instead of `_mint`\e[0m", description: "In favor of `_safeMint()`, which guarantees that the receiver is either an EOA or implements IERC721Receiver, `_mint()` is deprecated. References: [OpenZeppelin warning ERC721.sol#L271](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/d4d8d2ed9798cc3383912a23b5e8d5cb602f7d4b/contracts/token/ERC721/ERC721.sol#L271), [solmate _safeMint](https://github.com/transmissions11/solmate/blob/4eaf6b68202e36f67cab379768ac6be304c8ebde/src/tokens/ERC721.sol#L180), [OpenZeppelin _safeMint](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/d4d8d2ed9798cc3383912a23b5e8d5cb602f7d4b/contracts/token/ERC721/ERC721.sol#L238-L250).", issues: ""}
			issues_map << {key: :draft_openzeppelin, title: "\e[32mDraft OpenZeppelin dependencies\e[0m", description: "OpenZeppelin draft contracts may not have undergone sufficient security auditing or are subject to change as a result of upcoming development. Reference: [[L-02] Draft OpenZeppelin Dependencies | prePO contest](https://code4rena.com/reports/2022-12-prepo/#l-02-draft-openzeppelin-dependencies).", issues: ""}
			issues_map << {key: :use_of_blocktimestamp, title: "\e[32mTimestamp dependency: use of `block.timestamp` (or `now`)\e[0m", description: "The timestamp of a block is provided by the miner who mined the block. As a result, the timestamp is not guaranteed to be accurate or to be the same across different nodes in the network. In particular, an attacker can potentially mine a block with a timestamp that is favorable to them, known as \"selective packing\". For example, an attacker could mine a block with a timestamp that is slightly in the future, allowing them to bypass a time-based restriction in a smart contract that relies on `block.timestamp`. This could potentially allow the attacker to execute a malicious action that would otherwise be blocked by the restriction. It is reccomended to, instead, use an alternative timestamp source, such as an oracle, that is not susceptible to manipulation by a miner. References: [Timestamp dependence | Solidity Best Practices for Smart Contract Security](https://consensys.net/blog/developers/solidity-best-practices-for-smart-contract-security/), [What Is Timestamp Dependence?](https://halborn.com/what-is-timestamp-dependence/).", issues: ""}
			issues_map << {key: :calls_in_loop, title: "\e[32mUsage of calls inside of loop\e[0m", description: "A denial-of-service attack might result from calls made inside a loop. Reference: [Calls inside a loop | Slither](https://github.com/crytic/slither/wiki/Detector-Documentation#calls-inside-a-loop).", issues: ""}
			issues_map << {key: :outdated_pragma, title: "\e[32mOutdated Compiler Version\e[0m", description: "Using an older compiler version might be risky, especially if the version in question has faults and problems that have been made public. References: [SWC-102](https://swcregistry.io/docs/SWC-102), [Etherscan Solidity Bug Info](https://etherscan.io/solcbuginfo).", issues: ""}
			issues_map << {key: :ownableupgradeable, title: "\e[32mUse `Ownable2StepUpgradeable` instead of `OwnableUpgradeable` contract\e[0m", description: "It is recommended to use [Ownable2StepUpgradeable](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/Ownable2StepUpgradeable.sol) instead of OwnableUpgradeable contract. Reference: [[L-04] Use Ownable2StepUpgradeable instead of OwnableUpgradeable contract](https://code4rena.com/reports/2022-11-redactedcartel/#l-04-use-ownable2stepupgradeable-instead-of-ownableupgradeable-contract).", issues: ""}
			issues_map << {key: :ecrecover_addr_zero, title: "\e[32m`ecrecover()` does not check for `address(0)`\e[0m", description: "In the contract it was found the use of `ecrecover()` without implementing proper checks for `address(0)`. When a signature is incorrect, ecrecover may occasionally provide a random address rather than 0. It is also reccomended to implement the OpenZeppelin soludion [ECDSA.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol). Reference: [What is ecrecover in Solidity?](https://soliditydeveloper.com/ecrecover).", issues: ""}
			issues_map << {key: :dont_use_assert, title: "\e[32mUse `require` instead of `assert`\e[0m", description: "It is reccomended to use `require` instead of `assert` since the latest, when false, uses up all the remaining gas and reverts all the changes made. Reference: [Require vs Assert in Solidity](https://dev.to/tawseef/require-vs-assert-in-solidity-5e9d).", issues: ""}
			issues_map << {key: :deprecated_cl_library_function, title: "\e[32mDeprecated ChainLink library function\e[0m", description: "[As per Chainlink's documentation](https://docs.chain.link/data-feeds/api-reference), the contracts use deprecated ChainLink Library functions, it is recommend that you avoid using them.", issues: ""}
			issues_map << {key: :push_0_pragma, title: "\e[32mSolidity >= 0.8.20 `PUSH0` opcode incompatibility across EVM chains\e[0m", description: "Solidity compiler version 0.8.20 introduces a bytecode optimization that utilizes PUSH0 opcodes for gas efficiency. However, this may cause deployment issues on EVM implementations, such as certain L2 chains, that do not support PUSH0. It's crucial to consider the target deployment chain's compatibility and select the appropriate Solidity version or adjust the compiler settings to ensure seamless contract deployment.", issues: ""}

			# medium issues
			issues_map << {key: :single_point_of_control, title: "\e[33mCentralization risk detected: contract has a single point of control\e[0m", description: "Centralization risks are weaknesses that malevolent project creators as well as hostile outside attackers can take advantage of. They may be used in several forms of attacks, including rug pulls. When contracts have a single point of control, contract owners need to be trusted to prevent fraudulent upgrades and money draining since they have privileged access to carry out administrative chores. Some solutions to this issue include implementing timelocks and/or multi signature custody. Reference: [Trusting a Smart Contract Means Trusting Its Owners: Understanding Centralization Risk](https://arxiv.org/html/2312.06510v1), [UK Court Ordered Oasis to Exploit Own Security Flaw to Recover 120k wETH Stolen in Wormhole Hack](https://medium.com/@observer1/uk-court-ordered-oasis-to-exploit-own-security-flaw-to-recover-120k-weth-stolen-in-wormhole-hack-fcadc439ca9d).", issues: ""}
			issues_map << {key: :use_safemint_msgsender, title: "\e[33mNFT can be frozen in the contract, use `_safeMint` instead of `_mint`\e[0m", description: "The NFT can be frozen in the contract if `msg.sender` is an address for a contract that does not support ERC721. This means that users could lose their NFT. It is reccomended to use `_safeMint` instead of `_mint`. References: [EIP-721](https://eips.ethereum.org/EIPS/eip-721), [ERC721.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L274-L285).", issues: ""}
			issues_map << {key: :use_of_cl_lastanswer, title: "\e[33mUse of the deprecated `latestAnswer` function in contracts\e[0m", description: "[As per Chainlink's documentation](https://docs.chain.link/data-feeds/api-reference#latestanswer), the `latestAnswer` function is no longer recommended for use. This function does not generate an error in case no answer is available; instead, it returns 0, which could lead to inaccurate prices being provided to various price feeds or potentially result in a Denial of Service. It is recommended to use [`latestRoundData()`](https://docs.chain.link/data-feeds/api-reference#latestrounddata).", issues: ""}
			issues_map << {key: :solmate_not_safe, title: "\e[33mSafeTransferLib.sol does not check if a token is a contract or not\e[0m", description: "[As per Solmate's SafeTransferLib.sol](https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol#L9), the contract does not verify the existence of the token contract, delegating this responability to the caller. This creates the possiblity for a honeypot attack. An example is the [Qubit Finance hack in January 2022](https://www.halborn.com/blog/post/explained-the-qubit-hack-january-2022). Consider using [OpenZeppelin's SafeERC20](https://docs.openzeppelin.com/contracts/2.x/api/token/erc20#SafeERC20) instead.", issues: ""}

			# high issues
			issues_map << {key: :delegatecall_in_loop, title: "\e[31mUse of `delegatecall` inside of a loop\e[0m", description: "Using `delegatecall` in a payable function within a loop can pose a vulnerability where each call retains the `msg.value` of the initial transaction. This can lead to unexpected behaviors, especially in scenarios involving fund transfers. References: [\"Two Rights Might Make A Wrong\" by samczsun](https://www.paradigm.xyz/2021/08/two-rights-might-make-a-wrong)",issues: ""}
			issues_map << {key: :arbitrary_from_in_transferFrom, title: "\e[31mArbitrary `from` in `transferFrom` / `safeTransferFrom`\e[0m", description: "Allowing any `from` address to be passed to `transferFrom` (or `safeTransferFrom`) may result in potential loss of funds, as it enables anyone to transfer tokens from the designated address upon approval.", issues: ""}

			sol_files.each do |sol_file|
				
				issues_f = check_for_issues(sol_file[:contents])
				
				if !issues_f.empty?
					issues_f.each do |key, value|
						issues_map.each do |issue_map|
							if key.to_s == issue_map[:key].to_s
								issue_map[:issues] = issue_map[:issues] + "\n#{sol_file[:path]}#{value}" 
							end
						end
					end
				end
			end

			check_openzeppelin_version(directory, issues_map)

			issues_map.each do |issue_map|
				
				issue_title = issue_map[:title].delete("`")

				if issue_map[:issues].scan(/::\d{1,3}/).count > 0
					issue_map[:instances] = issue_map[:issues].scan(/::\d{1,3}/).count
				else
					issue_map[:instances] = (issue_map[:issues].scan '=>').count
				end

				puts "\n#{issue_title} Instances (#{issue_map[:instances]}) #{issue_map[:issues]}\n" if issue_map[:issues] != ""

			end

			end_time = Time.now
			execution_time = end_time - start_time
			create_report(issues_map, sol_files)
			puts "Analysis executed in \e[94m#{execution_time}\e[0m seconds"

		else
			puts "\n[\e[31m+\e[0m] ERROR: No solidity file found"
		end

	else
		puts "\n[\e[31m+\e[0m] ERROR: No directory found"
	end

rescue Exception => e
	puts "\n[\e[31m+\e[0m] ERROR: #{path}: #{e.message}"
end
