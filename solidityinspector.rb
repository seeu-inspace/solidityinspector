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
	line_check = line.gsub(" ","").gsub("\t","")
	line_check.start_with?("//") || line_check.start_with?("/*") || line_check.start_with?("*") || line_check.end_with?("*/")
end



def extract_pragma_version(solidity_file)
	pragma_line = solidity_file.split("\n").find { |line| line.start_with?("pragma solidity") }
	if pragma_line != nil
		pragma_line.match(/pragma solidity (.*?);/)[1]
	else
		"no_version_found"
	end
end



# check for the versions of @openzeppelin/contracts and @openzeppelin/contracts-upgradeable in package.json if they are < 4.7.3
# seeu https://code4rena.com/reports/2022-04-jpegd/#h-03-update-initializer-modifier-to-prevent-reentrancy-during-initialization
def check_dependencies(dependencies)

	if dependencies
		if dependencies['@openzeppelin/contracts']
			openzeppelin_version = dependencies['@openzeppelin/contracts']
			major, minor, patch = openzeppelin_version.gsub("^","").gsub(">","").gsub("<","").gsub("=","").split(".")
			if major.to_i < 4 || (major.to_i == 4 && (minor.to_i < 7 || (minor.to_i == 7 && patch.to_i < 3)))
				puts "\n\e[31mOutdated version of @openzeppelin/contracts\e[0m\n::package.json => Version of @openzeppelin/contracts is #{openzeppelin_version}"
			end
		end
			
		if dependencies['@openzeppelin/contracts-upgradeable']
			openzeppelin_version = dependencies['@openzeppelin/contracts-upgradeable']
			major, minor, patch = openzeppelin_version.gsub("^","").gsub(">","").gsub("<","").gsub("=","").split(".")
			if major.to_i < 4 || (major.to_i == 4 && (minor.to_i < 7 || (minor.to_i == 7 && patch.to_i < 3)))
				puts "\n\e[31mOutdated version of @openzeppelin/contracts-upgradeable\e[0m\n::package.json => Version of @openzeppelin/contracts-upgradeable is #{openzeppelin_version}"
			end
		end
		
	end

end

def check_openzeppelin_version(directory)

	package_json_path = File.join(directory, 'package.json')
	
	if File.exist?(package_json_path)
	
		package_json = JSON.parse(File.read(package_json_path))
		
		check_dependencies(package_json['devDependencies'])
		check_dependencies(package_json['dependencies'])

	end
	
end



def check_for_issues(solidity_file)
	issues = {}
	
	inside_loop = false

	pragma_version = extract_pragma_version(solidity_file)
	
	major, minor, patch = pragma_version.gsub("^","").gsub(">","").gsub("<","").gsub("=","").split(".")
	
	#gas issues
	issues[:use_recent_solidity] = issues[:use_recent_solidity].to_s + "\n => pragma solidity " + pragma_version + ";" if (minor.to_i < 8 || ( minor.to_i == 8 && patch.to_i < 10)) && pragma_version != "no_version_found"
	
	# qa issues
	# :: non-critical issues ::
	issues[:missing_spdx] = " => The Solidity file is missing the SPDX-License-Identifier" if !solidity_file.include?("SPDX-License-Identifier")
	# :: low issues ::
	issues[:unspecific_compiler_version_pragma] = " => pragma solidity " + pragma_version + ";" if pragma_version.include?("<") || pragma_version.include?(">") || pragma_version.include?(">=") || pragma_version.include?("<=") || pragma_version.include?("^")
	issues[:outdated_pragma] = issues[:outdated_pragma].to_s + " => #{pragma_version}" if (minor.to_i < 8 || ( minor.to_i == 8 && patch.to_i < 10)) && pragma_version != "no_version_found"
	
	#medium issues
	issues[:ownable_pausable] = issues[:ownable_pausable].to_s + " => This contract may be Ownable and Pausable" if solidity_file.include?("Ownable") && solidity_file.include?("Pausable")
	
	lines = solidity_file.split("\n")

	lines.each_with_index do |line, index|
	
		# template to add an issue:		issues[:KEY] = issues[:KEY].to_s + format if CONDITION
		format = "\n::#{index + 1} => #{line}"
	
		issues[:todo_unfinished_code] = issues[:todo_unfinished_code].to_s + format if line =~ /todo|to do/i
	
		next if is_comment?(line)
		
		# check if you are in a loop
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
		issues[:postfix_increment_unchecked] = issues[:postfix_increment_unchecked].to_s + format if (line.include?("++") || line.include?("--")) && !line.include?("unchecked{") && (minor.to_i > 8 || ( minor.to_i == 8 && patch.to_i >= 0)) && (line.include?("while") || line.include?("for"))  && pragma_version != "no_version_found"
		issues[:superfluous_event_fields] = issues[:superfluous_event_fields].to_s + format if (line.match?(/timestamp/) || line.include?("block.timestamp") || line.include?("block.number")) &&  line.include?("event")
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
		# :: low issues ::
		issues[:empty_body] = issues[:empty_body].to_s + format if line.match?(/(\{\})|(\{ \})/i) && !line.include?("//") && !line.include?("receive()")
		issues[:unsafe_erc20_operations] = issues[:unsafe_erc20_operations].to_s + format if line.match?(/\.transferFrom\(|\.increaseAllowance\(|\.decreaseAllowance\(/)
		issues[:deprecated_oz_library_functions] = issues[:deprecated_oz_library_functions].to_s + format if line.match?(/_setupRole\(|safeApprove\(|tokensOf\(/)		
		issues[:abiencoded_dynamic] = issues[:abiencoded_dynamic].to_s + format if line.include?("abi.encodePacked(") && line.include?("keccak256(")
		issues[:transfer_ownership] = issues[:transfer_ownership].to_s + format if line.match?(/.transferOwnership\(/)
		issues[:use_safemint] = issues[:use_safemint].to_s + format if line.match?(/_mint\(/)
		issues[:draft_openzeppelin] = issues[:draft_openzeppelin].to_s + format if line.include?("import") && line.include?("openzeppelin") && line.include?("draft")
		issues[:use_of_blocktimestamp] = issues[:use_of_blocktimestamp].to_s + format if line.include?("block.timestamp") || line.include?("now")
		issues[:calls_in_loop] = issues[:calls_in_loop].to_s + format if line.match?(/\.transfer\(|\.transferFrom\(|\.call|\.delegatecall/) && inside_loop
		issues[:ownableupgradeable] = issues[:ownableupgradeable].to_s + format if line.include?("OwnableUpgradeable")
		issues[:ecrecover_addr_zero] = issues[:ecrecover_addr_zero].to_s + format if line.include?("ecrecover(") && !line.include?("address(0)")
		issues[:dont_use_assert] = issues[:dont_use_assert].to_s + format if line.include?("assert(")
		
		# medium issues
		issues[:single_point_of_control] = issues[:single_point_of_control].to_s + format if line.match(/( onlyOwner )|( onlyRole\()|( requiresAuth )|(Owned)!?([(, ])|(Ownable)!?([(, ])|(Ownable2Step)!?([(, ])|(AccessControl)!?([(, ])|(AccessControlCrossChain)!?([(, ])|(AccessControlEnumerable)!?([(, ])|(Auth)!?([(, ])|(RolesAuthority)!?([(, ])|(MultiRolesAuthority)!?([(, ])/i)
		issues[:use_safemint_msgsender] = issues[:use_safemint_msgsender].to_s + format if line.match?(/_mint\(/) && line.include?("msg.sender")
		
		# check if you are not in a loop anymore
		if line.include?("}") && inside_loop
			inside_loop = false
		end
		
	end
	
	issues
	
end


# print the logo and start the script
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
			
			# template to add an issue:		issues_map << {key: :KEY, title: "\e[37mTITLE\e[0m", issues: ""}
			
			# gas issues
			issues_map << {key: :bool_storage_overhead, title: "\e[37mUsing bools for storage incurs overhead\e[0m", issues: ""}
			issues_map << {key: :cache_array_outside_loop, title: "\e[37mArray length not cached outside of loop\e[0m", issues: ""}
			issues_map << {key: :default_variable_initialization, title: "\e[37mVariables initialized with default value\e[0m", issues: ""}
			issues_map << {key: :shift_instead_of_divmul, title: "\e[37mMissing implementation Shift Right/Left for division and multiplication\e[0m", issues: ""}
			issues_map << {key: :use_diff_from_0, title: "\e[37mUnsigned integer comparison with > 0\e[0m", issues: ""}
			issues_map << {key: :long_revert_string, title: "\e[37mLong revert string\e[0m", issues: ""}
			issues_map << {key: :postfix_increment, title: "\e[37mPostfix increment/decrement used\e[0m", issues: ""}
			issues_map << {key: :non_constant_or_immutable_variables, title: "\e[37mVariable not constant/immutable\e[0m", issues: ""}
			issues_map << {key: :public_function, title: "\e[37mMake function external instead of public\e[0m", issues: ""}
			issues_map << {key: :revert_function_not_payable, title: "\e[37mMark payable functions guaranteed to revert when called by normal users\e[0m", issues: ""}
			issues_map << {key: :assembly_address_zero, title: "\e[37mUse assembly to check for address(0)\e[0m", issues: ""}
			issues_map << {key: :assert_instead_of_require, title: "\e[37mUse \"require\" instead of \"assert\" when possible\e[0m", issues: ""}
			issues_map << {key: :small_uints, title: "\e[37mUsage of uints/ints smaller than 32 bytes (256 bits) incurs overhead\e[0m", issues: ""}
			issues_map << {key: :use_selfbalance, title: "\e[37mUse selfbalance() instead of address(this).balance\e[0m", issues: ""}
			issues_map << {key: :use_immutable, title: "\e[37mUsage of constant keccak variables results in extra hashing\e[0m", issues: ""}
			issues_map << {key: :use_require_andand, title: "\e[37mSplit require() statements that use && to save gas\e[0m", issues: ""}
			issues_map << {key: :math_gas_cost, title: "\e[37mx += y costs more gas than x = x + y for state variables\e[0m", issues: ""}
			issues_map << {key: :postfix_increment_unchecked, title: "\e[37m++i/i++ should be unchecked{++i}/unchecked{i++} when it is not possible for them to overflow\e[0m", issues: ""}
			issues_map << {key: :superfluous_event_fields, title: "\e[37mSuperfluos event fields\e[0m", issues: ""}
			issues_map << {key: :bool_equals_bool, title: "\e[37mUse if(x) or if(!x) instead of if (x == bool)\e[0m", issues: ""}
			issues_map << {key: :strict_comparison, title: "\e[37mWhen possible, use non-strict comparison >= and/or =< instead of > <\e[0m", issues: ""}
			issues_map << {key: :private_rather_than_public, title: "\e[37mIf possible, use private rather than public for constants\e[0m", issues: ""}
			issues_map << {key: :use_recent_solidity, title: "\e[37mUse a more recent version of Solidity to save gas\e[0m", issues: ""}
			
			# qa issues
			# :: non-critical issues ::
			issues_map << {key: :require_revert_missing_descr, title: "\e[92mrequire()/revert() statements should have descriptive reason strings\e[0m", issues: ""}
			issues_map << {key: :unnamed_return_params, title: "\e[92mUnnamed return parameters\e[0m", issues: ""}
			issues_map << {key: :use_of_abi_encodepacked, title: "\e[92mUsage of abi.encodePacked instead of bytes.concat() for Solidity version >= 0.8.4\e[0m", issues: ""}
			issues_map << {key: :make_modern_import, title: "\e[92mFor modern and more readable code; update import usages\e[0m", issues: ""}
			issues_map << {key: :todo_unfinished_code, title: "\e[92mCode base comments with TODOs\e[0m", issues: ""}
			issues_map << {key: :missing_spdx, title: "\e[92mSPDX-License-Identifier missing\e[0m", issues: ""}
			issues_map << {key: :file_missing_pragma, title: "\e[92mFile is missing pragma\e[0m", issues: ""}
			# :: low issues ::
			issues_map << {key: :empty_body, title: "\e[92mConsider commenting why the body of the function is empty\e[0m", issues: ""}
			issues_map << {key: :unspecific_compiler_version_pragma, title: "\e[32mCompiler version Pragma is non-specific\e[0m", issues: ""}
			issues_map << {key: :unsafe_erc20_operations, title: "\e[32mUnsafe ERC20 operations\e[0m", issues: ""}
			issues_map << {key: :deprecated_oz_library_functions, title: "\e[32mDeprecated OpenZeppelin library functions\e[0m", issues: ""}
			issues_map << {key: :abiencoded_dynamic, title: "\e[32mAvoid using abi.encodePacked() with dynamic types when passing the result to a hash function\e[0m", issues: ""}
			issues_map << {key: :transfer_ownership, title: "\e[32mUse safeTransferOwnership instead of the transferOwnership method\e[0m", issues: ""}
			issues_map << {key: :use_safemint, title: "\e[32mUse _safeMint instead of _mint\e[0m", issues: ""}
			issues_map << {key: :draft_openzeppelin, title: "\e[32mDraft OpenZeppelin dependencies\e[0m", issues: ""}
			issues_map << {key: :use_of_blocktimestamp, title: "\e[32mTimestamp dependency: use of block.timestamp (or now)\e[0m", issues: ""}
			issues_map << {key: :calls_in_loop, title: "\e[32mUsage of calls inside of loop\e[0m", issues: ""}
			issues_map << {key: :outdated_pragma, title: "\e[32mOutdated Compiler Version\e[0m", issues: ""}
			issues_map << {key: :ownableupgradeable, title: "\e[32mUse Ownable2StepUpgradeable instead of OwnableUpgradeable contract\e[0m", issues: ""}
			issues_map << {key: :ecrecover_addr_zero, title: "\e[32mecrecover() does not check for address(0)\e[0m", issues: ""}
			issues_map << {key: :dont_use_assert, title: "\e[32mUse require instead of assert\e[0m", issues: ""}
			
			# medium issues
			issues_map << {key: :single_point_of_control, title: "\e[33mCentralization risk detected: contract has a single point of control\e[0m", issues: ""}
			issues_map << {key: :use_safemint_msgsender, title: "\e[33mNFT can be frozen in the contract, use _safeMint instead of _mint\e[0m", issues: ""}
			issues_map << {key: :ownable_pausable, title: "\e[33mDoS: The contract enables ownable and pausable at the same time\e[0m", issues: ""}
			

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

			issues_map.each do |issue_map|
				puts "\n#{issue_map[:title]} Instances (#{(issue_map[:issues].scan '=>').count}) #{issue_map[:issues]}\n" if issue_map[:issues] != ""
			end
			
		else
			puts "\n[\e[31m+\e[0m] ERROR: No solidity file found"
		end
		
		check_openzeppelin_version(directory)		
		
	else
		puts "\n[\e[31m+\e[0m] ERROR: No directory found"
	end

rescue Exception => e
	puts "\n[\e[31m+\e[0m] ERROR: #{path}: #{e.message}"
end
