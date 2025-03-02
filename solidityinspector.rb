#!/usr/bin/env ruby

require 'find'
require 'json'



TYPE_RANGES = {
	"uint8" => 2**8 - 1, "uint16" => 2**16 - 1, "uint32" => 2**32 - 1,
	"uint64" => 2**64 - 1, "uint128" => 2**128 - 1, "uint256" => 2**256 - 1,
	"int8" => 2**7 - 1, "int16" => 2**15 - 1, "int32" => 2**31 - 1,
	"int64" => 2**63 - 1, "int128" => 2**127 - 1, "int256" => 2**255 - 1
}

BUILTIN_SYMBOLS = %w[
	assert require revert block blockhash gasleft msg now tx this addmod mulmod 
	keccak256 sha256 sha3 ripemd160 ecrecover selfdestruct suicide abi fallback
	receive abstract after alias apply auto case catch copyof default define final
	immutable implements in inline let macro match mutable null of override partial
	promise reference relocatable sealed sizeof static supports switch try type
	typedef typeof unchecked
]

UNISWAP_SWAP_FUNCS = %w[
	swapExactTokensForTokens swapTokensForExactTokens swapExactETHForTokens
	swapTokensForExactETH swapExactTokensForETH swapETHForExactTokens
	swapExactTokensForTokensSupportingFeeOnTransferTokens
	swapExactETHForTokensSupportingFeeOnTransferTokens
	swapExactTokensForETHSupportingFeeOnTransferTokens
]



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



def count_lines_of_code(file_path)
	file = File.open(file_path, "r")
	lines_count = 0
	file.each_line do |line|
		lines_count += 1 if !line.strip.empty? && !is_comment?(line)
	end
	return lines_count
end



def extract_pragma_version(solidity_file)
	pragma_line = solidity_file.split("\n").find { |line| line.start_with?("pragma solidity") }
	pragma_line&.match(/pragma\s+solidity\s+(.*?);/)&.[](1) || "no_version_found"
end



def count_element_usage(solidity_file_content, element)
	solidity_file_content.scan(/#{element}\s*\(/).size
end



def version_compare?(version, threshold, comparison_type)
	return false if version.nil? || threshold.nil? || threshold.size < 3

	# Ensure version has three parts
	parts = version.split('.').map(&:to_i)
	major, minor, patch = parts[0] || 0, parts[1] || 0, parts[2] || 0

	case comparison_type
	when :less_than
		major < threshold[0] || 
		(major == threshold[0] && (minor < threshold[1] || 
		(minor == threshold[1] && patch < threshold[2])))
	when :more_than
		major > threshold[0] || 
		(major == threshold[0] && (minor > threshold[1] || 
		(minor == threshold[1] && patch > threshold[2])))
	else
		raise ArgumentError, "Invalid comparison type. Use :less_than or :more_than."
	end
end



def check_dependencies_issues(dependencies, issues_map)
	return unless dependencies

	if dependencies['@openzeppelin/contracts']
		openzeppelin_version = dependencies['@openzeppelin/contracts'].gsub(/[\^<>!=]/, '')
		if version_compare?(openzeppelin_version, [4, 9, 5], :less_than)
			issues_map << {
				key: :outdated_openzeppelin_contracts,
				title: "\e[31mOutdated version of openzeppelin-contracts\e[0m",
				description: "Implementing an outdated version of `@openzeppelin/contracts`, specifically prior to version 4.9.5, introduces multiple high severity issues into the protocol's smart contracts, posing significant security risks. Immediate updating is crucial to mitigate vulnerabilities and uphold the integrity and trustworthiness of the protocol's operations. [Check openzeppelin-contracts public reported and fixed security issues](https://github.com/OpenZeppelin/openzeppelin-contracts/security).",
				issues: "\n::package.json => Version of @openzeppelin/contracts is #{openzeppelin_version}",
				recommendations: "Upgrade to the latest stable version of `@openzeppelin/contracts` (>= 5.2.0). Ensure all contract dependencies remain compatible after the upgrade and thoroughly test the changes before deployment."
			}
		end
	end

	if dependencies['@openzeppelin/contracts-upgradeable']
		openzeppelin_version = dependencies['@openzeppelin/contracts-upgradeable'].gsub(/[\^<>!=]/, '')
		if version_compare?(openzeppelin_version, [4, 3, 0], :less_than)
			issues_map << {
				key: :outdated_openzeppelin_contracts_upgradeable,
				title: "\e[31mOutdated version of openzeppelin-contracts-upgradeable\e[0m",
				description: "Implementing an outdated version of `@openzeppelin/contracts-upgradeable`, specifically prior to version 4.3.5, introduces multiple high severity issues into the protocol's smart contracts, posing significant security risks. Immediate updating is crucial to mitigate vulnerabilities and uphold the integrity and trustworthiness of the protocol's operations. [Check openzeppelin-contracts public reported and fixed security issues](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/security).",
				issues: "\n::package.json => Version of @openzeppelin/contracts-upgradeable is #{openzeppelin_version}",
				recommendations: "Upgrade to the latest stable version of `@openzeppelin/contracts-upgradeable` (>= 5.2.0). Ensure all contract dependencies remain compatible after the upgrade and thoroughly test the changes before deployment."
			}
		end
	end
end



def check_openzeppelin_version(directory, issues_map)
	package_json_path = nil

	Find.find(directory) do |path|
		if File.basename(path) == 'package.json'
			package_json_path = path
			break
		end
	end

	if package_json_path && File.exist?(package_json_path)
		begin
			package_json = JSON.parse(File.read(package_json_path))
			check_dependencies_issues(package_json['devDependencies'], issues_map)
			check_dependencies_issues(package_json['dependencies'], issues_map)
		rescue => e
			puts "\n[\e[31m+\e[0m] ERROR: Error reading or parsing #{package_json_path}: #{e.message}"
		end
	end
end



def process_files_in_parallel(sol_files, issues_map)
	mutex = Mutex.new
	batch_size = [4, sol_files.size].min

	sol_files.each_slice(batch_size) do |batch|
		threads = batch.map do |sol_file|
			Thread.new do
				begin
					file_path = sol_file[:path]
					issues = check_for_issues(file_path, sol_file[:contents])
					
					mutex.synchronize do
						issues.each do |key, value|
							target = issues_map.find { |im| im[:key] == key }
							next unless target
							target[:issues] += "\n#{file_path}#{value}"
						end
					end
				rescue => e
					puts "Error processing #{file_path}: #{e.message}"
				end
			end
		end
		threads.each(&:join)
	end
end



def check_for_issues(solidity_file_path, solidity_file_content)

	lines = solidity_file_content.split("\n")

	issues = {}
	loop_depth = 0
	opening_brackets = 0
	variables = {}
	function_name = ""

	has_payable = false
	has_withdrawal = false
	current_function_visibility = nil
	current_function_payable = false
	current_function_pure_view = false
	has_inconsistent_types = false
	variables_modified_in_function = false
	current_function_emits_events = false

	pragma_version = extract_pragma_version(solidity_file_content)
	pragma_version_clean = pragma_version.gsub(/[\^<>!=]/, '')

	#gas issues
	issues[:use_recent_solidity] = issues[:use_recent_solidity].to_s + " => pragma solidity " + pragma_version + ";" if version_compare?(pragma_version_clean, [0, 8, 10], :less_than) && pragma_version != "no_version_found"

	# qa issues
	# :: non-critical issues ::
	issues[:missing_spdx] = " => The Solidity file is missing the SPDX-License-Identifier" if !solidity_file_content.include?("SPDX-License-Identifier")
	issues[:file_missing_pragma] = issues[:file_missing_pragma].to_s + " => no_version_found" if pragma_version == "no_version_found"
	issues[:safe_math_08] = issues[:safe_math_08].to_s + format if !version_compare?(pragma_version_clean, [0,8,0], :less_than) && solidity_file_content.include?("SafeMath")
	# :: low issues ::
	issues[:unspecific_compiler_version_pragma] = " => pragma solidity " + pragma_version + ";" if pragma_version.include?("<") || pragma_version.include?(">") || pragma_version.include?(">=") || pragma_version.include?("<=") || pragma_version.include?("^")
	issues[:outdated_pragma] = issues[:outdated_pragma].to_s + " => #{pragma_version}" if version_compare?(pragma_version_clean, [0, 8, 10], :less_than) && pragma_version != "no_version_found"
	issues[:push_0_pragma] = issues[:push_0_pragma].to_s + " => #{pragma_version}" if version_compare?(pragma_version_clean, [0, 8, 19], :more_than) && pragma_version != "no_version_found"
	issues[:upgradeable_missing_gap] = " => Contract appears upgradeable but missing __gap storage variable" if solidity_file_content.include?("Upgradeable") && !solidity_file_content.include?("__gap")

	lines.each_with_index do |line, index|

		next unless line

		# template to add an issue:		issues[:KEY] = issues[:KEY].to_s + format if CONDITION
		format = "\n::#{index + 1} => #{line}"

		issues[:todo_unfinished_code] = issues[:todo_unfinished_code].to_s + format if line =~ /todo|to do/i
	
		next if is_comment?(line)

		# Track function entry/exit and properties
		if line.include?('function')
			# Extract visibility and payable status
			match = line.match(/function\s+(\w+)\s*\((.*?)\)\s*(.*?)\s*{/)
			if match
				function_name = match[1]
				modifiers = match[3].downcase
	
				current_function_visibility = modifiers[/public|private|internal|external/, 0] || 'public'
				current_function_payable = modifiers.include?('payable')
				current_function_pure_view = modifiers.include?('pure') || modifiers.include?('view')

				# check for issues
				if current_function_visibility && count_element_usage(solidity_file_content, function_name) <= 1
					# gas issues
					issues[:public_function] = issues[:public_function].to_s + format if version_compare?(pragma_version_clean, [0, 6, 9], :less_than) && pragma_version != "no_version_found"
					# qa issues
					# :: low issues ::
					issues[:unused_internal_func] = issues[:unused_internal_func].to_s + format if current_function_visibility == 'internal'
					issues[:public_func_not_used_internally] = issues[:public_func_not_used_internally].to_s + format if current_function_visibility == 'public'
				end

				# reset loop counters
				loop_depth = 0
				opening_brackets = 0

			else
				current_function_visibility = 'public'
				current_function_payable = false
			end
		elsif line.include?('}') && current_function_visibility

			# qa issues
			# :: low issues ::
			# state_change_no_event
			if variables_modified_in_function && !current_function_emits_events && function_name != '' && !current_function_pure_view && function_name != 'initialize'
				issues[:state_change_no_event] = issues[:state_change_no_event].to_s + "\n::=> function #{function_name} lack event emission"
			end

			current_function_visibility = nil
			current_function_payable = false
			current_function_pure_view = false
			variables_modified_in_function = false
			current_function_emits_events = false

			# reset loop counters
			loop_depth = 0
			opening_brackets = 0
		end

		# Check for withdrawal operations in public/external functions
		if current_function_visibility && ['public', 'external'].include?(current_function_visibility)
			if line.include?('.transfer(') || line.include?('.send(') || line.include?('.call{value:') || line.include?('.call.value(')
				has_withdrawal = true
			end
		end

		# track variables declarations
		if line =~ /\b(uint\d*|int\d*|bool|address|bytes\d+|string|mapping)\b(?:\s+(?:public|private|internal|constant|memory|storage|calldata))*\s+([a-zA-Z_$]\w*)(?:\s*=\s*[^;]+)?;/
			var_type = $1
			var_name = $2
			variables[var_name] = { 
				type: var_type, 			# Store var type
				declared_line: index + 1,	# Store declaration line
			}
		end

		loop_depth += 1 if line.match?(/\b(for|while)\s*\(/)
		opening_brackets +=1 if line.include?("{")

		# gas issues
		issues[:bool_storage_overhead] = issues[:bool_storage_overhead].to_s + format if line.match?(/(bool.[a-z,A-Z,0-9]*.?=.?)|(bool.[a-z,A-Z,0-9]*.?;)|(=> bool)/) && !line.include?("function") && !line.include?("event")
		issues[:cache_array_outside_loop] = issues[:cache_array_outside_loop].to_s + format if ( line.include?(".length") || line.include?(".size") ) && ( line.include?("while") || line.include?("for") )
		issues[:default_variable_initialization] = issues[:default_variable_initialization].to_s + format if line.match?(/(uint[0-9]*[[:blank:]][a-z,A-Z,0-9]*.?=.?0;)|(bool.[a-z,A-Z,0-9]*.?=.?false;)/) || line.match?(/.?=.?0;/) && line.start_with?(/uint[0-9]*[[:blank:]][a-z,A-Z,0-9]/)
		issues[:shift_instead_of_divmul] = issues[:shift_instead_of_divmul].to_s + format if line.match?(/\/[2,4,8]|\/ [2,4,8]|\*[2,4,8]|\* [2,4,8]/)
		issues[:use_diff_from_0] = issues[:use_diff_from_0].to_s + format if line.match?(/>0|> 0/)
		issues[:long_revert_string] = issues[:long_revert_string].to_s + format if (line =~ /'[\w\d\s]{33,}'/ || line =~ /"[\w\d\s]{33,}"/) && !line.include?("keccak256")
		issues[:postfix_increment] = issues[:postfix_increment].to_s + format if line.include?("++") || line.include?("--")
		issues[:non_constant_or_immutable_variables] = issues[:non_constant_or_immutable_variables].to_s + format if (line.match?(/(uint[0-9]*[[:blank:]][a-z,A-Z,0-9]*.?=.?;)|(bool.[a-z,A-Z,0-9]*.?=.?;)/) || line.match?(/.?=.?;/) && line.start_with?(/uint[0-9]*[[:blank:]][a-z,A-Z,0-9]/)) && !line.match?(/immutable|constant/) && !line.include?("function")
		issues[:revert_function_not_payable] = issues[:revert_function_not_payable].to_s + format if (line.match?(/only/) && line.include?("function") && (line.include?("external") || line.include?("public"))) && !line.include?("payable")
		issues[:assembly_address_zero] = issues[:assembly_address_zero].to_s + format if line.include?("address(0)")
		issues[:assert_instead_of_require] = issues[:assert_instead_of_require].to_s + format if line.include?("assert(")
		issues[:small_uints] = issues[:small_uints].to_s + format if line.match?(/\buint(\d{1,2})\b|\bint(\d{1,2})\b/) && ($1.to_i < 32 || $2.to_i < 32) && line.include?("=")
		issues[:use_selfbalance] = issues[:use_selfbalance].to_s + format if line.include?("address(this).balance")
		issues[:use_immutable] = issues[:use_immutable].to_s + format if line.include?("keccak256(") && line.include?("constant") && version_compare?(pragma_version_clean, [0, 6, 12], :less_than) && pragma_version != "no_version_found"
		issues[:use_require_andand] = issues[:use_require_andand].to_s + format if line.include?("require(") && line.include?("&&")
		issues[:math_gas_cost] = issues[:math_gas_cost].to_s + format if line.include?("-=") || line.include?("+=")
		issues[:postfix_increment_unchecked] = issues[:postfix_increment_unchecked].to_s + format if (line.include?("++") || line.include?("--")) && !line.include?("unchecked{") && version_compare?(pragma_version_clean, [0, 8, 0], :more_than) && (line.include?("while") || line.include?("for")) && pragma_version != "no_version_found"
		issues[:superfluous_event_fields] = issues[:superfluous_event_fields].to_s + format if (line.match?(/timestamp/) || line.include?("block.timestamp") || line.include?("block.number")) && line.include?("event")
		issues[:bool_equals_bool] = issues[:bool_equals_bool].to_s + format if line.include?("==") && (line.include?("false") || line.include?("true"))
		issues[:strict_comparison] = issues[:strict_comparison].to_s + format if (line.include?(">") || line.include?("<")) && !line.include?("=")
		issues[:private_rather_than_public] = issues[:private_rather_than_public].to_s + format if line.match?(/(public.?constant.?|constant.?public.?)[^=\n\(]*(=|;)/i)

		# qa issues
		# :: non-critical issues ::
		issues[:require_revert_missing_descr] = issues[:require_revert_missing_descr].to_s + format if line.match?(/require\(|revert\(/) && !line.include?("\"")
		issues[:unnamed_return_params] = issues[:unnamed_return_params].to_s + format if line.include?("function") && line.include?("returns") && !line.end_with?(";")
		issues[:use_of_abi_encodepacked] = issues[:use_of_abi_encodepacked].to_s + format if line.match?(/abi.encodePacked\(/) && version_compare?(pragma_version_clean, [0, 8, 4], :more_than) && pragma_version != "no_version_found"
		issues[:make_modern_import] = issues[:make_modern_import].to_s + format if line.include?("import") && !line.include?("{")
		issues[:magic_numbers] = issues[:magic_numbers].to_s + format if (line.match?(/\b\d{2,}\b/) || line.match?(/-?\d\.?\d*[Ee][+\-]?\d+/) || line.match?(/\b\d{1,3}(?:_\d{3})+\b/)) && !line.include?("pragma") && !line.include?("int")
		issues[:costly_loop_operations] = issues[:costly_loop_operations].tot_s + format if loop_depth > 0 && line.match(/[a-zA-Z0-9_]+\s*=\s*.*/) && line.include?("=") && (line.include?(".storage") || line.include?(" sstore"))
		issues[:empty_blocks] = issues[:empty_blocks].to_s + format if line.match(/\{\s*\}/) && !line.match?(/constructor|receive|fallback|catch|payable/)
		issues[:large_literals] = issues[:large_literals].to_s + format if line.match(/\b\d{5,}\b/) && !line.include?("0x") && !line.include?("e")
		issues[:abicoder_v2] = issues[:abicoder_v2].to_s + format if line.match?(/pragma.*abicoder.*v2/i)
		issues[:abi_encode_unsafe] = issues[:abi_encode_unsafe].to_s + format if line.match?(/(encodeWithSignature|encodeWithSelector)/i)
		issues[:control_structure_style] = issues[:control_structure_style].to_s + format if line.match?(/\bif\s*\(.*\)\s*[^{]/) && !line.include?("{")
		issues[:long_lines] = issues[:long_lines].to_s + format if line.length >= 164
		issues[:mapping_style] = issues[:mapping_style].to_s + format if line.match?(/mapping\s*\(\s/)
		issues[:hardcoded_address] = issues[:hardcoded_address].to_s + format if line.match?(/0x[a-fA-F0-9]{40}(\)|;)/)
		issues[:scientific_notation_exponent] = issues[:scientific_notation_exponent].to_s + format if line.match?(/10\s*\*\*\s*\d/i)
		## => inconsistent_types
		if line =~ /\b(uint\d*|int\d*)\b/ && !line.include?("function") && !line.include?("returns") # Capture uint/int types
			var_type = $1

			# Define tracking hash if not initialized
			seen_types ||= { 'uint' => false, 'uint256' => false, 'int' => false, 'int256' => false }

			# Detect inconsistent types
			has_inconsistent_types = true if seen_types.values_at('uint', 'uint256').uniq == [true] || seen_types.values_at('int', 'int256').uniq == [true]

			# Mark type as seen
			seen_types[var_type] = true
		end
		# track if we are in a function and a variable has been modified
		if current_function_visibility
			variables_modified_in_function = true  && line.match(/\b[a-zA-Z_]\w*\s*=\s*/)
			current_function_emits_events = true if current_function_visibility && line.match(/emit\s+([\w\.]+)\(/)
		end
		# Check if constants are in CONSTANT_CASE
		if line.match?(/(constant|immutable)\s+([a-zA-Z0-9_]+)/)
			var_name = $2
			unless var_name == var_name.upcase
				issues[:constant_naming] = issues[:constant_naming].to_s + format
			end
		end
		# :: low issues ::
		issues[:empty_body] = issues[:empty_body].to_s + format if line.match?(/(\{\})|(\{ \})/i) && !line.include?("//") && !line.include?("receive()")
		issues[:unsafe_erc20_operations] = issues[:unsafe_erc20_operations].to_s + format if line.match?(/\.transferFrom\(|\.transfer\(|\.approve\(|\.increaseAllowance\(|\.decreaseAllowance\(/)
		issues[:deprecated_oz_library_functions] = issues[:deprecated_oz_library_functions].to_s + format if line.match?(/_setupRole\(|safeApprove\(|tokensOf\(/)		
		issues[:abiencoded_dynamic] = issues[:abiencoded_dynamic].to_s + format if line.include?("abi.encodePacked(") && line.include?("keccak256(")
		issues[:transfer_ownership] = issues[:transfer_ownership].to_s + format if line.match?(/\.transferOwnership\(/)
		issues[:draft_openzeppelin] = issues[:draft_openzeppelin].to_s + format if line.include?("import") && line.include?("openzeppelin") && line.include?("draft")
		issues[:use_of_blocktimestamp] = issues[:use_of_blocktimestamp].to_s + format if line.include?("block.timestamp")
		issues[:calls_in_loop] = issues[:calls_in_loop].to_s + format if line.match?(/\.transfer\(|\.transferFrom\(|\.call|\.delegatecall/) && loop_depth > 0
		issues[:ownableupgradeable] = issues[:ownableupgradeable].to_s + format if line.include?("OwnableUpgradeable")
		issues[:ecrecover_addr_zero] = issues[:ecrecover_addr_zero].to_s + format if line.include?("ecrecover(") && !line.include?("address(0)")
		issues[:dont_use_assert] = issues[:dont_use_assert].to_s + format if line.include?("assert(")
		issues[:deprecated_cl_library_function] = issues[:dont_use_assert].to_s + format if line.match?(/\.getTimestamp\(|\.getAnswer\(|\.latestRound\(|\.latestTimestamp\(/)
		issues[:shadowed_global] = issues[:shadowed_global].to_s + format if ((line =~ /\b(uint\d*|int\d*|bool|address|bytes\d+|string|mapping)\b(?:\s+(?:public|private|internal|constant|memory|storage|calldata))*\s+([a-zA-Z_$]\w*)(?:\s*=\s*[^;]+)?;/ && BUILTIN_SYMBOLS.include?($2)) || (line.start_with?('function') && line =~ /function\s+(\w+)/ && BUILTIN_SYMBOLS.include?($1)))
		issues[:assembly_in_constant] = issues[:assembly_in_constant].to_s + format if current_function_pure_view && line.include?("assembly")
		issues[:reverts_in_loops] = issues[:reverts_in_loops].to_s + format if loop_depth > 0 && (line.include?("require(") || line.include?("revert"))
		issues[:decimals_not_erc20] = issues[:decimals_not_erc20].to_s + format if line.match?(/\.decimals\(\)/)
		issues[:decimals_not_uint8] = issues[:decimals_not_uint8].to_s + format if line.match?(/uint(?!8)(?!.*(\/\/|;)).*decimals/)
		issues[:fallback_lacking_payable] = issues[:fallback_lacking_payable].to_s + format if line.match?(/fallback(?!.*payable)/i)
		issues[:symbol_not_erc20] = issues[:symbol_not_erc20].to_s + format if line.match?(/\.symbol\(\)/)
		issues[:hardcoded_year] = issues[:hardcoded_year].to_s + format if line.match?(/\byear\s*[=+]\s*365\b/i) && !line.include?("365 days")
		issues[:dangerous_while_loop] = issues[:dangerous_while_loop].to_s + format if line.match(/while\s*\(\s*true\s*\)/i)
		## => unused_error
		if line.include?("error ") && !solidity_file_path.include?("Error")
			error_name = line.scan(/error (\w+)/).flatten.first
			if count_element_usage(solidity_file_content, error_name) <= 1
				issues[:unused_error] = issues[:unused_error].to_s + format
			end
		end
		## => uniswap_block_timestamp_deadline
		if line.match?(/#{UNISWAP_SWAP_FUNCS.join('|')}/)
			args = line.scan(/\((.*?)\)/).last&.first.to_s.split(',').map(&:strip)
			issues[:uniswap_block_timestamp_deadline] = issues[:uniswap_block_timestamp_deadline].to_s + format if args.last&.include?("block.timestamp")
		end

		# medium issues
		issues[:single_point_of_control] = issues[:single_point_of_control].to_s + format if line.match(/( onlyOwner )|( onlyRole\()|( requiresAuth )|(Owned)!?([(, ])|(Ownable)!?([(, ])|(Ownable2Step)!?([(, ])|(AccessControl)!?([(, ])|(AccessControlCrossChain)!?([(, ])|(AccessControlEnumerable)!?([(, ])|(Auth)!?([(, ])|(RolesAuthority)!?([(, ])|(MultiRolesAuthority)!?([(, ])/i)
		issues[:use_safemint] = issues[:use_safemint].to_s + format if line.match?(/_mint\(/)
		issues[:use_of_cl_lastanswer] = issues[:use_of_cl_lastanswer].to_s + format if line.match?(/\.latestAnswer\(/)
		issues[:solmate_not_safe] = issues[:solmate_not_safe].to_s + format if line.match?(/\.safeTransferFrom\(|.safeTransfer\(|\.safeApprove\(/) && solidity_file_content.include?("SafeTransferLib.sol")
		issues[:nested_loop] = issues[:nested_loop].to_s + format if ((line.include?("for (") || line.include?("while (")) && line.include?("{")) && loop_depth > 1
		issues[:unchecked_recover] = issues[:unchecked_recover].to_s + format if line.match?(/\.recover\([^)]*\)\s*;/) && !line.match?(/=/)
		issues[:unchecked_transfer_transferfrom] = issues[:unchecked_transfer_transferfrom].to_s + format if line.match?(/\.(transfer|transferFrom)\([^)]*\)\s*;/) && !line.match?(/=/)
		issues[:use_of_blocknumber] = issues[:use_of_blocknumber].to_s + format if line.match?(/\bblock\.number\b/)
		issues[:stale_check_missing] = issues[:stale_check_missing].to_s + format if line.match?(/\.latestRoundData\s*\(/) && line.match?(/\(\s*,\s*int256\s+\w+,\s*,\s*,\s*\)/)

		# high issues
		issues[:delegatecall_in_loop_payable] = issues[:delegatecall_in_loop_payable].to_s + format if line.match?(/\.delegatecall\(/) && loop_depth > 0 && current_function_payable
		issues[:msgvalue_in_loop] = issues[:msgvalue_in_loop].to_s + format if line.match?(/msg\.value/) && loop_depth > 0
		## arbitrary_from_in_transferFrom
		if line.match?(/\btransferFrom\s*\(/) || line.match?(/\bsafeTransferFrom\s*\(/)
			# Extracting the first argument within parentheses
			first_arg = line.match(/\b(?:transferFrom|safeTransferFrom)\s*\(\s*([^\s,]+)/)&.captures&.first
			if first_arg && first_arg != "msg.sender"
				issues[:arbitrary_from_in_transferFrom] = issues[:arbitrary_from_in_transferFrom].to_s + format
			end
		end
		## detect unsafe casting
		if line.match(/(\buint\d+|\bint\d+)\s+\w+\s*=\s*(\1)\(.+?\)/)
			casted_type = $1
			original_type = $2
	
			var_name = line.match(/=\s*#{original_type}\((\w+)\)/i)&.captures&.first
			original_type = variables.dig(var_name, :type) if var_name
	
			issues[:unsafe_casting] = issues[:unsafe_casting].to_s + format if TYPE_RANGES[original_type] && TYPE_RANGES[casted_type] && TYPE_RANGES[casted_type] < TYPE_RANGES[original_type]
		end
		issues[:get_dy_underlying_flash_loan] = issues[:get_dy_underlying_flash_loan].to_s + format if line.match?(/get_dy_underlying\(/i)
		issues[:wsteth_price_steth] = issues[:wsteth_price_steth].to_s + format if line.match?(/(price.*\*.*WstETH.*stEthPerToken|WstETH.*stEthPerToken.*\*.*price)/i)
		issues[:yul_return_usage] = issues[:yul_return_usage].to_s + format if line.include?("return") && line.match?(/assembly\s*{/)
		issues[:rtlo_character] = issues[:rtlo_character].to_s + format if line.include?("\u202E")
		issues[:multiple_retryable_calls] = issues[:multiple_retryable_calls].to_s + format if line.match?(/(createRetryableTicket|outboundTransferCustomRefund|unsafeCreateRetryableTicket)/)

		# check if you are not in a loop anymore. This also check if there are more closing brackets than loop_depth
		opening_brackets -= 1 if line.include?("}") && loop_depth < opening_brackets
		if line.match("}") && loop_depth == opening_brackets && loop_depth > 0
			loop_depth -= 1
			opening_brackets -= 1
		end


	end

	# Add issue if payable exists but no withdrawal
	issues[:contract_locks_ether] = " => Contract can accept Ether but lacks a withdrawal function" if has_payable && !has_withdrawal

	# Add inconsistent type
	issues[:inconsistent_types] = " => Contract has inconsistent uint/int declarations" if has_inconsistent_types

	issues

end



def create_report(issues_map, sol_files)
	buffer = []
	severity_order = [:high, :medium, :low, :non_critical, :gas]
	category_titles = {
		high: "High Issues",
		medium: "Medium Issues",
		low: "Low Issues",
		non_critical: "Non-Critical Issues",
		gas: "Gas Issues"
	}

	# --- Preprocessing Phase ---
	issues_map.each do |issue|
		issue[:instances] = issue[:issues].scan(/::\d{1,3}|=>/).count
		issue[:total_gas] = (issue[:gas] || 0) * issue[:instances]
		
		issue[:sanitized_title] = issue[:title].gsub(/\e\[\d+m/, '')
			.gsub(/([a-z])([A-Z])/, '\1 \2')	# Add space before capital letters
			.gsub(/[^\w\s-]/, '')
			.tr(' ', '-')
			.downcase
			.squeeze('-')

		issue[:category] = case issue[:title]
		when /\e\[31m/ then :high
		when /\e\[33m/ then :medium
		when /\e\[32m/ then :low
		when /\e\[92m/ then :non_critical
		when /\e\[37m/ then :gas
		else :other
		end
	end

	# --- Data Organization ---
	categorized = issues_map.group_by { |i| i[:category] }
		.transform_values { |v| v.reject { |i| i[:issues].empty? } }
		.select { |k,v| category_titles.key?(k) }

	# --- Report Header ---
	buffer << "# SolidityInspector Analysis Report\n\n"
	buffer << "This report was generated by [SolidityInspector](https://github.com/seeu-inspace/solidityinspector), " \
					"a tool made by [Riccardo Malatesta (@seeu)](https://riccardomalatesta.com/). " \
					"The purpose of this report is to assist in the process of identifying potential security weaknesses " \
					"and should not be relied upon for any other use.\n\n"

	# --- Table of Contents ---
	buffer << "## Table of Contents\n\n"
	buffer << "- [Summary](#summary)"
	buffer << "\t- [Files Analyzed](#files-analyzed)"
	buffer << "\t- [Issues Found](#issues-found)"

	severity_order.each do |cat|
		next unless categorized.key?(cat)
		issues = categorized[cat]
		buffer << "- [#{category_titles[cat]}](##{cat}-issues)"
		issues.each_with_index do |issue, idx|
			id_prefix = case cat
							when :high then "H"
							when :medium then "M" 
							when :low then "L"
							when :non_critical then "NC"
							when :gas then "G"
							end
			id = "#{id_prefix}-#{'%02d' % (idx+1)}:"
			title = issue[:title].gsub(/\e\[\d+m/, '').gsub(/([a-z])([A-Z])/, '\1 \2')
			anchor = "#{id.downcase.gsub(':','')}-#{issue[:sanitized_title]}"
			buffer << "\t- [#{id} #{title}](##{anchor})"
		end
	end
	buffer << "\n"

	# --- Summary Section ---
	buffer << "## Summary\n\n"

	# Files Analyzed
	buffer << "### Files Analyzed\n\n"
	buffer << "| Filepath | SLOC |\n| --- | --- |"
	sol_files.each { |file| buffer << "| #{file[:path]} | #{count_lines_of_code(file[:path])} |" }
	buffer << "\n"

	# Issues Found
	buffer << "### Issues Found\n\n"
	buffer << "| Category | Number of Issues Found |\n| --- | --- |"
	severity_order.each do |cat|
		next unless categorized.key?(cat)
		issues = categorized[cat]
		count = issues.count { |i| i[:instances] > 0 }
		buffer << "| #{category_titles[cat]} | #{count} |" if count > 0
	end
	buffer << "\n"

	# --- Category Sections ---
	severity_order.each do |cat|
		next unless categorized.key?(cat)
		issues = categorized[cat]
		next if issues.empty?
		total_gas = cat == :gas ? issues.sum { |i| i[:total_gas] } : 0

		buffer << "\n## #{category_titles[cat]}\n\n"
		
		# Table Header
		columns = cat == :gas ? ["ID", "Issue", "Instances", "Gas Saved"] : ["ID", "Issue", "Instances"]
		buffer << "| #{columns.join(' | ')} |"
		buffer << "|#{' --- |' * columns.count}"

		# Table Rows
		issues.each_with_index do |issue, idx|
			id_prefix = case cat
							when :high then "H"
							when :medium then "M" 
							when :low then "L"
							when :non_critical then "NC"
							when :gas then "G"
							end
			id = "#{id_prefix}-#{'%02d' % (idx+1)}"
			title = issue[:title].gsub(/\e\[\d+m/, '').gsub(/([a-z])([A-Z])/, '\1 \2')
			anchor = "#{id.downcase.gsub(':','')}-#{issue[:sanitized_title]}"
			title_anchor = "[#{id} #{title}](##{anchor})"

			row = [id, title_anchor, issue[:instances]]
			row << "~#{issue[:total_gas]}" if cat == :gas

			buffer << "| #{row.join(' | ')} |"
		end

		# Gas Total
		if cat == :gas
			buffer << "| **Total** | | **#{issues.sum { |i| i[:instances] }}** | **~#{total_gas}** |"
		end

		buffer << "\n"

		# Detailed Findings
		issues.each_with_index do |issue, idx|
			id_prefix = case cat
							when :high then "H"
							when :medium then "M" 
							when :low then "L"
							when :non_critical then "NC"
							when :gas then "G"
							end
			id = "#{id_prefix}-#{'%02d' % (idx+1)}"
			title = issue[:title].gsub(/\e\[\d+m/, '').gsub(/([a-z])([A-Z])/, '\1 \2')

			buffer << "### #{id}: #{title}\n"
			buffer << "#{issue[:description]}\n"
			buffer << "#### Findings\n"
			buffer << "```solidity#{issue[:issues]}\n```\n"
			buffer << "#### Recommendations\n\n#{issue[:recommendations]}\n\n"
		end
	end

	File.write("solidityinspector_report.md", buffer.join("\n"))
	puts "\nReport generated: \e[94msolidityinspector_report.md\e[0m"
end



logo

begin

	current_dir = Dir.pwd

	dir_entries = Dir.entries(current_dir)

	directories = dir_entries.select { |entry| File.directory?(entry) && !['.','..'].include?(entry) }

	puts "Subdirectories in the current directory:"
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

	print "\e[93m┌─\e[0m Enter the path of the out-of-scope file [leave blank if not needed]:\n\e[93m└─\e[0m "
	out_of_scope_file = gets.chomp

	start_time = Time.now

	out_of_scope_paths = []

	# Read the out-of-scope paths from the file and remove the './' prefix (if there is)
	if !out_of_scope_file.empty? && File.exist?(out_of_scope_file)
		out_of_scope_paths = File.readlines(out_of_scope_file).map do |line|
			line.chomp.start_with?(/\.\//) ? line.chomp.sub(/^\.\//, '') : line.chomp
		end
	end

	if File.exist?(directory) && File.directory?(directory)

		sol_files = []

		Find.find(directory) do |path|
			begin

				next unless File.file?(path) && File.extname(path) == '.sol'

				# Check if the file is out of scope
				next if out_of_scope_paths.include?(path.sub(/^\.\//, ''))

				sol_files << { path: path, contents: File.read(path) }

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

			# template to add an issue:		issues_map << {key: :KEY, title: "\e[37mTITLE\e[0m", description: "",issues: "", recommendations: ""}

			# gas issues
			issues_map << {
				key: :bool_storage_overhead,
				title: "\e[37mAvoid Using Boolean Variables for Storage\e[0m",
				description: "Storing boolean values (`bool`) in Solidity incurs unnecessary gas costs. Using `uint256` (1 for true, 0 for false) eliminates additional `Gwarmaccess` (100 gas) and prevents costly `Gsset` operations (20,000 gas) when toggling from `false` to `true`. This simple adjustment can save up to 17,100 gas per instance.\n\nReference: [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27).",
				issues: "",
				gas: 17100,
				recommendations: <<~RECOMMENDATIONS
				Replace `bool` with `uint256` (1 for true, 0 for false).
				```solidity
				// Before
				bool public isActive = true;
				
				// After
				uint256 public isActive = 1; // 1 = true, 0 = false
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :cache_array_outside_loop,
				title: "\e[37mCache Array Length Before Looping\e[0m",
				description: "Failing to cache an array's length before a loop causes Solidity to repeatedly access `arr.length`, leading to redundant stack operations (`DUP<N>`). Storing the length in a variable optimizes execution by reducing stack manipulation, saving 3 gas per instance.",
				issues: "",
				gas: 3,
				recommendations: <<~RECOMMENDATIONS
				Cache array length before loop.
				```solidity
				// Before
				uint256 length = arr.length;
				for (uint256 i; i < length; i++) {
					// ... logic
				}
			
				// After
				uint256 length = arr.length;
				for (uint256 i; i < length; ) {
					// ... logic
					unchecked { ++i; }
				}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :default_variable_initialization,
				title: "\e[37mRemove Explicit Default Value Assignments\e[0m",
				description: "Solidity automatically initializes variables to their default values. Explicitly setting them (e.g., `uint256 x = 0;`) wastes gas and increases bytecode size. Simply declaring the variable without an explicit assignment removes unnecessary operations.",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Remove explicit initialization.
				```solidity
				// Before
				uint256 x = 0;
				
				// After
				uint256 x;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :shift_instead_of_divmul,
				title: "\e[37mUse Bitwise Shifting Instead of Multiplication and Division\e[0m",
				description: "Bitwise shifting (`<<` and `>>`) is more gas-efficient than multiplication (`*`) and division (`/`). The `SHR` opcode consumes only 3 gas, whereas `DIV` requires 5 gas. Additionally, shifting can bypass Solidity's division-by-zero restrictions",
				issues: "",
				gas: 2,
				recommendations: <<~RECOMMENDATIONS
				Use bitwise shifts.
				```solidity
				// Before
				x = y * 8;
				
				// After
				x = y << 3; // Equivalent to y * 2^3
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :use_diff_from_0,
				title: "\e[37mPrefer `!= 0` Over `> 0` for Unsigned Integers\e[0m",
				description: "For unsigned integer comparisons, `!= 0` is cheaper than `> 0`. This minor change reduces gas consumption in conditions and validation checks.",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Use `!= 0`.
				```solidity
				// Before
				require(x > 0);
				
				// After
				require(x != 0);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :long_revert_string,
				title: "\e[37mOptimize `revert` and `require` Strings to Reduce Gas Costs\e[0m",
				description: "Error messages in `require()` and `revert()` that exceed 32 bytes incur additional gas costs due to how Solidity handles string storage. Using custom errors instead of long revert strings significantly reduces gas consumption and bytecode size.",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Use custom errors or shorten strings.
				```solidity
				// Before
				revert("Long error message");
				
				// After
				error ShortError();
				revert ShortError();
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :postfix_increment,
				title: "\e[37mPostfix Increment/Decrement Increases Gas Costs\e[0m",
				description: "Using the prefix (`++i` / `--i`) increment or decrement is more gas-efficient than the postfix (`i++` / `i--`) versions. The prefix form updates the value before returning it, whereas the postfix form first returns the original value and then updates it.\nWhen the return value is not needed, using the prefix version avoids unnecessary storage operations, reducing gas usage. However, ensure correctness when refactoring, as `uint a = i++` and `uint a = ++i` produce different results.\n\nReference: [Why does ++i cost less gas than i++?](https://ethereum.stackexchange.com/questions/133161/why-does-i-cost-less-gas-than-i#answer-133164).",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Use prefix increment.
				```solidity
				// Before
				i++;
				
				// After
				++i;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :non_constant_or_immutable_variables,
				title: "\e[37mUse `constant` or `immutable` for Unchanging Variables\e[0m",
				description: "If a variable does not need to change, declaring it as `constant` or `immutable` reduces gas costs by eliminating the need for `SLOAD` operations. `constant` is used for compile-time constants, while `immutable` allows assignment in the constructor but prevents modifications afterward. Using these keywords optimizes storage access and reduces transaction fees.",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Add `immutable`/`constant`.
				```solidity
				// Before
				uint256 public value;
				
				// After
				uint256 public immutable value;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :public_function,
				title: "\e[37mUse `external` Instead of `public` for Functions When Possible\e[0m",
				description: "Since Solidity `0.6.9`, public functions must transfer calldata parameters to memory, incurring additional gas costs. Using `external` instead avoids unnecessary memory allocation when the function is only called externally. `external` functions cannot be called internally, so ensure they are not required within the contract before making this change.",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Change the visibility from `public` to `external`.
				```solidity
				// Before
				function foo() public {}
				
				// After
				function foo() external {}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :revert_function_not_payable,
				title: "\e[37mMark Functions as `payable` When They Are Guaranteed to Revert for Normal Users\e[0m",
				description: "If a function has a modifier like `onlyOwner` and would revert when called by a normal user sending ETH, marking it as `payable` optimizes gas usage. Making the function `payable` prevents the compiler from inserting checks to ensure no ETH was sent, avoiding unnecessary opcodes such as `CALLVALUE`, `DUP1`, `ISZERO`, and `REVERT`. This optimization reduces gas costs by approximately 21 gas per call and lowers deployment costs.",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Add `payable` to the interested functions.
				```solidity
				// Before
				function withdraw() external onlyOwner {}
				
				// After
				function withdraw() external payable onlyOwner {}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :assembly_address_zero,
				title: "\e[37mUse Assembly to Check for `address(0)` to Reduce Gas Costs\e[0m",
				description: "Checking for `address(0)` using Solidity's higher-level syntax incurs additional gas costs due to function calls or storage reads. Using inline assembly is more efficient and can save 6 gas per instance by leveraging the `iszero` opcode directly.",
				issues: "",
				gas: 6,
				recommendations: <<~RECOMMENDATIONS
				Implement inline assembly check.
				```solidity
				// Before
				require(addr != address(0));
			
				// After
				assembly {
					if iszero(addr) {
						revert(0, 0)
					}
				}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :assert_instead_of_require,
				title: "\e[37mUse `require` Instead of `assert` When Possible\e[0m",
				description: "When `assert()` fails, it triggers the `INVALID` (`0xfe`) opcode, consuming all remaining gas and reverting the transaction entirely. In contrast, `require()` uses the `REVERT` (`0xfd`) opcode, which allows unused gas to be returned. Using `require()` instead of `assert()` where appropriate can prevent unnecessary gas wastage while still enforcing conditions effectively.\n\nReference: [Assert() vs Require() in Solidity - Key Difference & What to Use](https://codedamn.com/news/solidity/assert-vs-require-in-solidity).",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Replace `assert` with `require`.
				```solidity
				// Before
				assert(condition);
				
				// After
				require(condition);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :small_uints,
				title: "\e[37mUsing `uint` or `int` Smaller Than 32 Bytes Incurs Overhead\e[0m",
				description: "The Ethereum Virtual Machine (EVM) processes data in 32-byte (256-bit) chunks. When using smaller integer types like `uint8` or `uint16`, the EVM must perform additional operations to adjust the size, leading to higher gas costs. To optimize gas efficiency, use `uint256` unless explicit packing within a struct is required.\n\nReference: [Layout of State Variables in Storage | Solidity Docs](https://docs.soliditylang.org/en/v0.8.11/internals/layout_in_storage.html#layout-of-state-variables-in-storage).",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Use `uint256` unless packing.
				```solidity
				// Before
				uint8 smallVar = 100;
				
				// After
				uint256 normalVar = 100;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :use_selfbalance,
				title: "\e[37mUse `selfbalance()` Instead of `address(this).balance` to Reduce Gas Costs\e[0m",
				description: "The `BALANCE` opcode, used when calling `address(this).balance`, has a minimum gas cost of 100. In contrast, `SELFBALANCE` is a more optimized opcode that only costs 5 gas, making it significantly more efficient for retrieving the contract's balance. Using `selfbalance()` within an inline assembly block minimizes gas costs while achieving the same functionality.\n\nReferences: [BALANCE | EVM Codes](https://www.evm.codes/#31?fork=merge), [SELFBALANCE | EVM Codes](https://www.evm.codes/#47?fork=merge).",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Use `selfbalance` in assembly.
				```solidity
				// Before
				uint256 bal = address(this).balance;
				
				// After
				uint256 bal;
				assembly { bal := selfbalance() }
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :use_immutable,
				title: "\e[37mUsing `constant` for Keccak Variables Causes Extra Hashing and Higher Gas Costs\e[0m",
				description: "Declaring `keccak256` hash values as `constant` results in additional hashing operations, increasing gas costs. Using `immutable` instead reduces gas consumption by approximately 20 gas, as the hash is computed only once during contract deployment. If the hash value does not need to be known at compile time, prefer `immutable` over `constant` to optimize gas efficiency.",
				issues: "",
				gas: 20,
				recommendations: <<~RECOMMENDATIONS
				If possible, use `immutable` instead of `constant`.
				```solidity
				// Before
				bytes32 constant HASH = keccak256("hash");
				
				// After
				bytes32 immutable HASH = keccak256("hash");
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :use_require_andand,
				title: "\e[37mSplitting `require()` Statements That Use `&&` Can Reduce Gas Costs\e[0m",
				description: "Using a single `require()` statement with the `&&` operator incurs additional gas costs due to stack operations and evaluation logic. Splitting the condition into two separate `require()` statements can save approximately 8 gas per instance by simplifying execution flow.",
				issues: "",
				gas: 8,
				recommendations: <<~RECOMMENDATIONS
				Split require statements into multiple checks.
				```solidity
				// Before
				require(a && b);
				
				// After
				require(a);
				require(b);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :math_gas_cost,
				title: "\e[37mUsing `x = x + y` Instead of `x += y` for State Variables Saves Gas\e[0m",
				description: "For state variables, using `x += y` or `x -= y` generates additional read and write operations compared to explicitly writing `x = x + y`. This optimization can save approximately 10 gas per instance by reducing unnecessary storage accesses.\n\nReference: [StateVarPlusEqVsEqPlus.md](https://gist.github.com/IllIllI000/cbbfb267425b898e5be734d4008d4fe8).",
				issues: "",
				gas: 10,
				recommendations: <<~RECOMMENDATIONS
				Use explicit assignment.
				```solidity
				// Before
				x += y;
				
				// After
				x = x + y;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :postfix_increment_unchecked,
				title: "\e[37mUse `unchecked{++i}` or `unchecked{i++}` When Overflow Is Not Possible\e[0m",
				description: "Starting from Solidity `0.8.0`, arithmetic operations include overflow checks by default, which increase gas costs. Wrapping increment (`++i` or `i++`) inside an `unchecked` block can save 30-40 gas per loop iteration when it is guaranteed that no overflow can occur.",
				issues: "",
				gas: 30,
				recommendations: <<~RECOMMENDATIONS
				Wrap the increment operation inside an `unchecked` block when it is certain that no overflow can occur.
				```solidity
				for (uint256 i = 0; i < n; ) {
					unchecked { ++i; }
					// loop body
				}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :superfluous_event_fields,
				title: "\e[37mRemove Redundant Event Fields to Save Gas\e[0m",
				description: "Including `block.number` or `block.timestamp` as event parameters is unnecessary, as these values are already recorded in the transaction logs by default. Removing them reduces event emission costs without losing essential information.",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Remove redundant fields.
				```solidity
				// Before
				event Log(uint256 value, uint256 timestamp);
				
				// After
				event Log(uint256 value); // timestamp is auto-added
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :bool_equals_bool,
				title: "\e[37mSimplify Boolean Comparisons to Reduce Gas and Complexity\e[0m",
				description: "Comparing boolean variables to `true` or `false` is unnecessary and adds extra computation. Instead of `if (x == true)`, simply use `if (x)`, and instead of `if (x == false)`, use `if (!x)`. This reduces gas costs and improves code readability.",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Simplify boolean checks.
				```solidity
				// Before
				if (x == true) {}
				
				// After
				if (x) {}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :strict_comparison,
				title: "\e[37mUse `>=` or `<=` Instead of `>` or `<` to Reduce Gas Costs\e[0m",
				description: "Non-strict comparisons (`>=` and `<=`) are more gas-efficient than strict comparisons (`>` and `<`) because they avoid additional `ISZERO` checks. This optimization can save 15-20 gas per instance. Adjust thresholds accordingly when making this change.",
				issues: "",
				gas: 15,
				recommendations: <<~RECOMMENDATIONS
				Use `>=`/`<=`.
				```solidity
				// Before
				require(x > 100);
				
				// After
				require(x >= 101);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :private_rather_than_public,
				title: "\e[37mUse `private` Instead of `public` for Constants to Reduce Deployment Gas\e[0m",
				description: "Marking constants as `public` generates an automatic getter function, which increases deployment costs by 3406-3606 gas. Since constant values can be retrieved from the verified contract source or through a dedicated getter function returning multiple values, using `private` avoids unnecessary storage and method ID table entries.",
				issues: "",
				gas: 3406,
				recommendations: <<~RECOMMENDATIONS
				Mark constants as `private` instead of `public`.
				```solidity
				// Before
				uint256 public constant VALUE = 100;
				
				// After
				uint256 private constant VALUE = 100;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :use_recent_solidity,
				title: "\e[37mUse a More Recent Solidity Version to Optimize Gas Usage\e[0m",
				description: "Upgrading to Solidity `0.8.10` or later provides multiple gas optimizations: skipping contract existence checks for external calls with return values (from `0.8.10`), using cheaper custom errors instead of revert strings (from `0.8.4`), improved struct packing and more efficient multiple storage reads (from `0.8.3`), and automatic compiler inlining (from `0.8.2`).",
				issues: "",
				gas: 0,
				recommendations: <<~RECOMMENDATIONS
				Update pragma to a more recent version.
				```solidity
				// Before
				pragma solidity ^0.8.0;
				
				// After
				pragma solidity ^0.8.20;
				```
				RECOMMENDATIONS
			}

			# qa issues
			# :: non-critical issues ::
			issues_map << {
				key: :require_revert_missing_descr,
				title: "\e[92mAdd Descriptive Reason Strings to `require()` and `revert()` Statements\e[0m",
				description: "Providing clear error messages in `require()` and `revert()` improves code readability and debugging. When a condition fails, an informative message helps identify the issue quickly, making the contract easier to maintain and troubleshoot.\n\nReference: [Error Handling: Assert, Require, Revert, and Exceptions](https://docs.soliditylang.org/en/v0.8.17/control-structures.html#error-handling-assert-require-revert-and-exceptions).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Include error messages in `require`/`revert` statements.
				```solidity
				// Before
				require(condition);

				// After
				require(condition, "Condition not met: insufficient balance");
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :unnamed_return_params,
				title: "\e[92mUse Named Return Parameters to Improve Readability\e[0m",
				description: "Naming return parameters in function declarations increases code clarity and explicitness. It makes function outputs easier to understand and improves maintainability by providing context for returned values.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Name return parameters in function declarations
				```solidity
				// Before
				function getUser() external returns (uint256);

				// After
				function getUser() external returns (uint256 userId);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :use_of_abi_encodepacked,
				title: "\e[92mUse `bytes.concat()` Instead of `abi.encodePacked()` for Solidity ≥ `0.8.4`\e[0m",
				description: "Starting from Solidity `0.8.4`, `bytes.concat()` provides a more readable alternative to `abi.encodePacked()` for concatenating `bytes` and `bytesNN` arguments. It offers the same functionality with a clearer name, improving code maintainability.\n\nReferences: [Solidity 0.8.4 Release Announcement](https://blog.soliditylang.org/2021/04/21/solidity-0.8.4-release-announcement/), [Remove abi.encodePacked #11593](https://github.com/ethereum/solidity/issues/11593).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Replace `abi.encodePacked` with `bytes.concat` for readability (Solidity ≥0.8.4).
				```solidity
				// Before
				bytes memory data = abi.encodePacked(a, b);

				// After
				bytes memory data = bytes.concat(a, b);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :make_modern_import,
				title: "\e[92mUse Explicit Imports for Improved Readability and Efficiency\e[0m",
				description: "To ensure only the necessary components are imported, use curly braces to specify individual imports. This makes the code more readable and helps avoid unnecessary dependencies.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use explicit imports with curly braces.
				```solidity
				// Before
				import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

				// After
				import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :todo_unfinished_code,
				title: "\e[92mRemove or Track `TODO` Comments to Maintain Code Quality\e[0m",
				description: "Unresolved `TODO` comments should be tracked in an issue backlog to ensure they are addressed before deployment. All `TODOs` must be completed or explicitly managed to prevent unfinished code from reaching production.",
				issues: "",
				recommendations: "Remove TODOs or track them in an issue tracker."
			}
			issues_map << {
				key: :missing_spdx,
				title: "\e[92mAdd `SPDX-License-Identifier` to Avoid Legal and Usage Issues\e[0m",
				description: "Including an `SPDX-License-Identifier` at the top of each Solidity file clarifies the licensing terms, preventing potential legal disputes and ensuring proper code usage.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Add the SPDX license identifier at the top of each Solidity file.
				```solidity
				// SPDX-License-Identifier: MIT
				pragma solidity ^0.8.20;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :file_missing_pragma,
				title: "\e[92mAdd a `pragma` Statement to Ensure Compiler Compatibility\e[0m",
				description: "Without a `pragma` statement, the contract may be compiled with an unintended Solidity version, leading to compatibility issues and unpredictable behavior. Explicitly specifying the Solidity version ensures stability and consistency.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Specify the Solidity version in files missing it.
				```solidity
				// Add to the top of the file
				pragma solidity ^0.8.20;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :empty_body,
				title: "\e[92mAdd a Comment to Explain Empty Function Bodies\e[0m",
				description: "If a function has an empty body, include a comment to clarify its purpose. This improves code readability and helps other developers understand the intent behind the function.",
				issues: "",
				recommendations: "Add a comment to explain why a function is empty."
			}
			issues_map << {
				key: :magic_numbers,
				title: "\e[92mReplace Magic Numbers with Named Constants for Better Readability\e[0m",
				description: "Embedding numeric literals directly into the code reduces readability, maintainability, and security. Instead, define meaningful constants or variables to provide context and improve transparency.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use named constants for numeric values.
				```solidity
				// Before
				uint256 deadline = block.timestamp + 86400;

				// After
				uint256 constant DAY_IN_SECONDS = 86400;
				uint256 deadline = block.timestamp + DAY_IN_SECONDS;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :public_func_not_used_internally,
				title: "\e[92mUse `external` Instead of `public` for Functions Not Called Internally\e[0m",
				description: "If a `public` function is never used within the contract, changing its visibility to `external` can reduce gas costs and improve contract efficiency. `external` functions are optimized for external calls and do not generate unnecessary internal access overhead.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Change visibility from `public` to `external` if not called internally.
				```solidity
				// Before
				function getBalance() public view returns (uint256) {}

				// After
				function getBalance() external view returns (uint256) {}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :empty_blocks,
				title: "\e[92mEmpty code blocks\e[0m",
				description: "Empty code blocks provide no functionality and can make the contract harder to read and maintain. They may also indicate incomplete implementations or leftover code that was not properly removed.",
				issues: "",
				recommendations: "To improve code clarity, remove any unnecessary empty blocks. If an empty block is required for structural reasons, add a comment explaining its purpose to prevent confusion during audits and future development."
			}
			issues_map << {
				key: :costly_loop_operations,
				title: "\e[92mCostly storage operations inside loops\e[0m",
				description: "Performing `SSTORE` operations inside loops is inefficient and significantly increases gas consumption. Each write to storage incurs a high gas cost, which can make transactions more expensive and even lead to out-of-gas errors if the loop iterates too many times.",
				issues: "",
				recommendations: "Cache values in memory by using local variables inside the loop and write to storage only once after the loop completes. This reduces redundant storage writes and improves contract efficiency."
			}
			issues_map << {
				key: :large_literals,
				title: "\e[92mLarge Numeric Literals\e[0m",
				description: "Using large numeric literals directly in code can make it harder to read, understand, and maintain. Numbers with many digits increase the likelihood of typos and errors, making debugging more difficult.",
				issues: "",
				recommendations: "Use scientific notation (`e` notation) instead of long numeric literals. For example, replace `1000000000000000000` with `1e18` to represent one Ether in wei."
			}
			issues_map << {
				key: :inconsistent_types,
				title: "\e[92mInconsistent Integer Declarations\e[0m", 
				description: "Using a mix of `uint` and `uint256` or `int` and `int256` within the same contract can lead to inconsistencies, making the code harder to read and maintain. While `uint` is an alias for `uint256`, explicitly specifying `uint256` improves clarity, ensures consistency across the codebase, and aligns with best practices.",
				issues: "",
				recommendations: "It is reccomended to use `uint256` and `int256` explicitly instead of relying on shorthand types."
			}
			issues_map << {
				key: :state_change_no_event,
				title: "\e[92mLack of Event Emission for State Changes\e[0m",
				description: "Changing state variables without emitting an event makes it difficult for off-chain services, dApps, and users to track contract activity. Events provide a reliable way to monitor state changes without requiring expensive storage reads, improving transparency and auditability.",
				issues: "",
				recommendations: "It is advised to emit relevant events whenever an important state change occurs. This allows external listeners to efficiently track changes and respond accordingly without needing to query the blockchain."
			}
			issues_map << {
				key: :abicoder_v2,
				title: "\e[92mRedundant `abicoder v2` Pragma in Solidity `0.8.0+`\e[0m",
				description: "The `abicoder v2` pragma is unnecessary in Solidity `0.8.0` and later, as it is enabled by default. Keeping this pragma in the code has no effect and may cause confusion regarding its necessity.",
				issues: "",
				recommendations: "It is advised to remove `pragma abicoder v2;` from Solidity files when using Solidity `0.8.0` or higher."
			}
			issues_map << {
				key: :abi_encode_unsafe,
				title: "\e[92mPotential Type Safety Issues When Using `abi.encodeWithSignature` or `abi.encodeWithSelector`\e[0m",
				description: "Manually encoding function calls with `abi.encodeWithSignature` or `abi.encodeWithSelector` can introduce errors due to typos in function signatures or incorrect parameter ordering. These issues may lead to failed transactions or unintended behavior.",
				issues: "",
				recommendations: "To enhance type safety and prevent errors, use `abi.encodeCall`, which ensures that function signatures and argument types match the expected function definition."
			}
			issues_map << {
				key: :constant_naming,
				title: "\e[92mConstants Should Use CONSTANT_CASE\e[0m",
				description: "Constant variables should follow the `CONSTANT_CASE` naming convention, where names are written in uppercase letters with underscores separating words. This improves readability, aligns with Solidity best practices, and makes constants easily distinguishable from regular variables.",
				issues: "",
				recommendations: "Rename constants to use CONSTANT_CASE (e.g., `MAX_VALUE`)."
			}
			issues_map << {
				key: :control_structure_style,
				title: "\e[92mInconsistent Formatting of Control Structures\e[0m",
				description: "Control structures, such as `if`, `for`, and `while`, should follow a consistent style to improve readability and maintainability. Opening braces should be placed on the same line as the condition to align with Solidity's best practices and commonly accepted style guides.",
				issues: "",
				recommendations: "To maintain a clean and consistent codebase, it is advised to format control structures as `if (condition) { ... }` instead of placing the opening brace on a new line."
			}
			issues_map << {
				key: :dangerous_while_loop,
				title: "\e[92mRisk of Infinite Execution Due to `while(true)` Loops\e[0m",
				description: "Using `while(true)` creates a loop with no explicit termination condition, which can lead to infinite execution. In Solidity, this can cause transactions to run out of gas, resulting in failed execution and wasted gas fees.",
				issues: "",
				recommendations: "To prevent infinite loops, replace `while(true)` with a loop that has a well-defined termination condition. If an indefinite loop is necessary, ensure that there is an explicit break condition to allow for controlled exits."
			}
			issues_map << {
				key: :long_lines,
				title: "\e[92mReduced Readability Due to Excessively Long Lines\e[0m",
				description: "Lines exceeding 164 characters can negatively impact readability, especially in code review tools like GitHub, where horizontal scrolling is required. Long lines make it harder to spot errors and understand logic at a glance.",
				issues: "",
				recommendations: "To improve code readability and maintainability, break long lines into multiple lines using proper formatting. Consider using indentation, line breaks, and helper variables to keep the code structured and easy to follow."
			}
			issues_map << {
				key: :mapping_style,
				title: "\e[92mInconsistent `mapping` Formatting Reduces Readability\e[0m",
				description: "Mappings in Solidity should be declared without spaces between `mapping` and the opening parenthesis to maintain consistency with the Solidity Style Guide. Inconsistent formatting can reduce readability and make code harder to review.\n\nReference: [Solidity Style Guide - Mappings](https://docs.soliditylang.org/en/latest/style-guide.html#mappings).",
				issues: "",
				recommendations: "To improve clarity and adhere to best practices, declare mappings in the following format: `mapping(address => uint256) balances;` instead of `mapping (address => uint256) balances;`."
			}
			issues_map << {
				key: :hardcoded_address,
				title: "\e[92mHard-Coded Addresses Reduce Flexibility and Maintainability\e[0m",
				description: "Using hard-coded addresses in a contract can lead to issues when deploying to different networks or environments. If an address changes due to an upgrade or redeployment, all instances of the contract that rely on the hard-coded value will need to be updated and redeployed, increasing the risk of errors and maintenance overhead.",
				issues: "",
				recommendations: "It is advised to replace hard-coded addresses with `immutable` variables that are initialized in the constructor."
			}
			issues_map << {
				key: :safe_math_08,
				title: "\e[92mRedundant Use of SafeMath in Solidity 0.8+\e[0m",
				description: "Starting from Solidity 0.8.0, built-in overflow and underflow checks are enabled by default, making the use of `SafeMath` unnecessary. Continuing to use `SafeMath` in newer Solidity versions adds unnecessary complexity and gas overhead without providing additional security benefits.",
				issues: "",
				recommendations: "To simplify the code and optimize gas efficiency, remove `SafeMath` and use native arithmetic operations directly. Solidity 0.8+ automatically reverts on overflow and underflow, ensuring safe arithmetic operations without requiring an external library."
			}
			issues_map << {
				key: :scientific_notation_exponent,
				title: "\e[92mUse of Exponentiation Instead of Scientific Notation\e[0m",
				description: "Using exponentiation (e.g., `10**18`) in Solidity can make numerical values harder to read and understand at a glance. Scientific notation (`1e18`) is more concise, improves clarity, and is widely recognized in Solidity and other programming languages.",
				issues: "",
				recommendations: "It is advised to replace exponentiation with scientific notation. For example, use `1e18` instead of `10**18` when representing large numbers like wei-to-ether conversions. This approach makes the code more intuitive and reduces potential misunderstandings."
			}
			# :: low issues ::
			issues_map << {
				key: :unspecific_compiler_version_pragma,
				title: "\e[32mUse a Fixed Solidity Version to Ensure Consistent Compilation\e[0m",
				description: "For non-library contracts, floating pragmas (`^0.8.0`) may introduce security risks by allowing compilation with unintended or vulnerable Solidity versions. Using a specific compiler version ensures that the contract is compiled consistently across different environments.\n\nReference: [Version Pragma | Solidity Documentation](https://docs.soliditylang.org/en/latest/layout-of-source-files.html#version-pragma).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use a fixed Solidity version to ensure consistent compilation.
				```solidity
				// Before
				pragma solidity ^0.8.0;
				
				// After
				pragma solidity 0.8.20;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :unsafe_erc20_operations,
				title: "\e[32mUse `SafeERC20` to Prevent Unsafe ERC20 Operations\e[0m",
				description: "ERC20 tokens have multiple implementations, some of which do not follow the standard correctly. Using OpenZeppelin's `SafeERC20` helps prevent issues by handling failures safely. If `SafeERC20` is not used, ensure each operation is wrapped in a `require` statement to check for successful execution.\n\nReference: [ERC20 OpenZeppelin Documentation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol#L43).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use SafeERC20 for ERC20 operations.
				```solidity
				// Before
				token.transferFrom(msg.sender, address(this), amount);
				
				// After
				import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
				SafeERC20.safeTransferFrom(token, msg.sender, address(this), amount);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :deprecated_oz_library_functions,
				title: "\e[32mAvoid Using Deprecated OpenZeppelin Library Functions\e[0m",
				description: "Some OpenZeppelin library functions have been deprecated and should be replaced with their modern equivalents. Using outdated functions may lead to compatibility issues and security risks. Always refer to the latest OpenZeppelin documentation to ensure best practices.\n\nReference: [OpenZeppelin Contracts Issue #1064](https://github.com/OpenZeppelin/openzeppelin-contracts/issues/1064).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Replace deprecated functions with modern equivalents.
				```solidity
				// Before
				_setupRole(DEFAULT_ADMIN_ROLE, admin);
				
				// After
				_grantRole(DEFAULT_ADMIN_ROLE, admin);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :abiencoded_dynamic,
				title: "\e[32mAvoid Using `abi.encodePacked()` with Dynamic Types When Hashing\e[0m",
				description: "Using `abi.encodePacked()` with dynamic types before hashing can lead to hash collisions due to improper padding. Instead, use `abi.encode()`, which ensures all values are padded to 32 bytes. If there is only one dynamic argument, consider casting it to `bytes()` or `bytes32()` before hashing. When concatenating multiple dynamic types, use `bytes.concat()` instead of `abi.encodePacked()`.\n\nReference: [Solidity ABI Specification - Non-Standard Packed Mode](https://docs.soliditylang.org/en/v0.8.13/abi-spec.html#non-standard-packed-mode), [How to Compare Strings in Solidity?](https://ethereum.stackexchange.com/questions/30912/how-to-compare-strings-in-solidity#answer-82739).",
				issues: "",
				recommendations: "Replace `abi.encodePacked()` with `abi.encode()` when dealing with dynamic types. This prevents hash collisions due to improper padding. If there is only a single dynamic argument, consider casting to `bytes()` or `bytes32()` before hashing. When concatenating multiple dynamic types, use `bytes.concat()` instead of `abi.encodePacked()`."
			}
			issues_map << {
				key: :transfer_ownership,
				title: "\e[32mUse `safeTransferOwnership` Instead of `transferOwnership` for Safer Ownership Transfers\e[0m",
				description: "The `transferOwnership` function transfers contract ownership in a single step, which can lead to accidental ownership loss. Using a two-step process like `safeTransferOwnership` improves security by requiring the new owner to accept ownership explicitly.\n\nReference: [OpenZeppelin Ownable2Step](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable2Step.sol).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Implement two-step ownership transfer.
				```solidity
				// Before
				transferOwnership(newOwner);
				
				// After
				import "@openzeppelin/contracts/access/Ownable2Step.sol";
				safeTransferOwnership(newOwner);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :draft_openzeppelin,
				title: "\e[32mAvoid Using Draft OpenZeppelin Contracts\e[0m",
				description: "Draft OpenZeppelin contracts may not be fully audited and are subject to changes, which can introduce security risks and instability. To ensure reliability, replace draft imports with stable, production-ready versions.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Replace draft imports with stable versions.
				```solidity
				// Before
				import "@openzeppelin/contracts/drafts/ERC20Permit.sol";
				
				// After
				import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :use_of_blocktimestamp,
				title: "\e[32mAvoid Relying on `block.timestamp` for Critical Logic\e[0m",
				description: "The block timestamp is set by the miner and can be manipulated within a small range, making it unreliable for critical operations like time-based restrictions. This vulnerability, known as \"selective packing\", can be exploited to bypass contract logic. For better security, use an external timestamp source such as an oracle, which is less susceptible to manipulation.\n\nReferences: [Timestamp Dependence | Solidity Best Practices](https://consensys.net/blog/developers/solidity-best-practices-for-smart-contract-security/), [What Is Timestamp Dependence?](https://halborn.com/what-is-timestamp-dependence/).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use oracle-based timestamps for critical logic.
				```solidity
				// Before
				require(block.timestamp > deadline, "Expired");
				
				// After
				uint256 oracleTimestamp = chainlinkOracle.getTimestamp();
				require(oracleTimestamp > deadline, "Expired");
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :calls_in_loop,
				title: "\e[32mAvoid Making External Calls Inside Loops\e[0m",
				description: "Calling external contracts inside a loop can lead to denial-of-service (DoS) attacks if one of the calls fails or takes too long to execute. This can also result in excessive gas consumption, making transactions more expensive or even causing them to fail. To mitigate this risk, consider batching operations or restructuring the code to minimize external calls within loops.",
				issues: "",
				recommendations: "Restructure code to avoid external calls in loops."
			}
			issues_map << {
				key: :outdated_pragma,
				title: "\e[32mUpgrade to a Recent Solidity Version to Avoid Security Risks\e[0m",
				description: "Using an outdated Solidity compiler version can expose the contract to known vulnerabilities and missing optimizations. Always use a recent version (`≥0.8.10`) to benefit from security patches, gas optimizations, and improved features.\n\nReference: [Etherscan Solidity Bug Info](https://etherscan.io/solcbuginfo).",
				issues: "",
				recommendations: "Upgrade to a recent Solidity version (Solidity ≥0.8.10)"
			}
			issues_map << {
				key: :ownableupgradeable,
				title: "\e[32mUse `Ownable2StepUpgradeable` Instead of `OwnableUpgradeable` for Safer Ownership Transfers\e[0m",
				description: "Replacing `OwnableUpgradeable` with `Ownable2StepUpgradeable` improves security by introducing a two-step ownership transfer process. This prevents accidental loss of ownership and enhances contract safety.\n\nReference: [Ownable2StepUpgradeable](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/Ownable2StepUpgradeable.sol).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Implement Ownable2StepUpgradeable instead of OwnableUpgradeable.
				```solidity
				// Before
				import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
				
				// After
				import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :ecrecover_addr_zero,
				title: "\e[32mEnsure `ecrecover()` Does Not Return `address(0)`\e[0m",
				description: "Using `ecrecover()` without checking for `address(0)` can lead to incorrect signature validation, as `ecrecover()` may return a random address instead of `0` for an invalid signature. Always include a check to reject zero addresses. It is also recommended to use OpenZeppelin's [ECDSA.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol) for safer and more reliable signature verification.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Add a check for zero address.
				```solidity
				address recovered = ecrecover(...);
				require(recovered != address(0), "Invalid signature");
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :dont_use_assert,
				title: "\e[32mUse `require` Instead of `assert` to Prevent Gas Wastage\e[0m",
				description: "`assert()` consumes all remaining gas when it fails, whereas `require()` allows unused gas to be refunded. Use `require()` for input validation and conditions to prevent unnecessary gas loss and improve contract efficiency.\n\nReference: [Require vs Assert in Solidity](https://dev.to/tawseef/require-vs-assert-in-solidity-5e9d).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Replace `assert` with `require`.
				```solidity
				// Before
				assert(condition);
				
				// After
				require(condition, "Condition failed");
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :deprecated_cl_library_function,
				title: "\e[32mAvoid Using Deprecated Chainlink Library Functions\e[0m",
				description: "Chainlink has deprecated functions like `getTimestamp`, `getAnswer`, `latestRound`, and `latestTimestamp`. Using outdated functions can lead to compatibility issues and missing improvements. It is recommended to update contracts to use the latest Chainlink Data Feeds functions, such as `latestRoundData()`, to ensure reliability and accuracy.\n\nReference: [Chainlink Data Feeds API Reference](https://docs.chain.link/data-feeds/api-reference).",
				issues: "",
				recommendations: "Update the contract to use the latest Chainlink Data Feeds functions, such as `latestRoundData()` or other recommended functions."
			}
			issues_map << {
				key: :push_0_pragma,
				title: "\e[32mEnsure Compatibility with `PUSH0` Opcode When Using Solidity `≥ 0.8.20`\e[0m",
				description: "Solidity `0.8.20` introduces the `PUSH0` opcode for gas optimization, but some EVM implementations, including certain Layer 2 chains, may not support it. Deploying contracts on incompatible chains could lead to failures. To avoid deployment issues, verify the target chain's support for `PUSH0`. If incompatibilities exist, consider downgrading the Solidity compiler to a version below `0.8.20` or use compiler flags to disable `PUSH0` optimizations.",
				issues: "",
				recommendations: "Verify the target deployment chain's support for the `PUSH0` opcode. If compatibility issues exist, downgrade the Solidity compiler to a version below 0.8.20 or use compiler flags to disable `PUSH0` optimizations. Consider using `solc` with appropriate settings to ensure seamless deployment across different EVM implementations."
			}
			issues_map << {
				key: :unused_error,
				title: "\e[32mRemove or Implement Unused Error Declarations\e[0m",
				description: "Some errors are declared but never used in the contract. Unused errors can add unnecessary complexity and should be reviewed to determine if they are needed. If not required, they should be removed or commented out to keep the code clean and maintainable.",
				issues: "",
				recommendations: "It is advised to remove or implement unused errors."
			}
			issues_map << {
				key: :shadowed_global,
				title: "\e[32mAvoid Shadowing Built-In Global Symbols\e[0m",
				description: "Using variable or function names that shadow built-in global symbols like `now`, `msg`, or `block` can lead to confusion and unintended behavior. To improve readability and prevent potential issues, rename such variables and functions in order to avoid conflicts.",
				issues: "",
				recommendations: "It is advised to rename variables and functions to avoid shadowing."
			}
			issues_map << {
				key: :div_before_mul,
				title: "\e[32mPerform Multiplication Before Division to Prevent Precision Loss\e[0m",
				description: "In Solidity, integer division truncates decimals, which can lead to precision loss if division is performed before multiplication. To maintain accuracy, always reorder operations to multiply first and then divide.\n\nReference: [Solidity Integer Division](https://docs.soliditylang.org/en/latest/types.html#division).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Reorder operations to multiply first.
				```solidity
				// Before
				uint256 result = (a / b) * c;
				
				// After
				uint256 result = (a * c) / b;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :uniswap_block_timestamp_deadline,
				title: "\e[32mLack of Protection When Using `block.timestamp` for Swap Deadlines\e[0m",
				description: "Relying on `block.timestamp` for swap deadlines provides no security against manipulation. In Proof-of-Stake (PoS) networks, block proposers can predict and reorder transactions within a block, potentially executing swaps under more favorable conditions. This can expose users to front-running risks and manipulated execution timing.",
				issues: "",
				recommendations: "Allow users to specify deadline parameters rather than defaulting to `block.timestamp`. This ensures greater control over transaction execution and reduces the risk of manipulation."
			}
			issues_map << {
				key: :unused_internal_func,
				title: "\e[32mUnused Internal Functions\e[0m",
				description: "Internal functions that are never called within the contract may indicate dead code, increasing contract size unnecessarily and potentially causing confusion during audits. Keeping unused functions can also introduce security risks if they become accessible through future upgrades or integrations.",
				issues: "",
				recommendations: "Remove any internal functions that are not in use. If the function is intended for external use, consider changing its visibility to `public` or `external` to clarify its purpose."
			}
			issues_map << {
				key: :assembly_in_constant,
				title: "\e[32mPotential Side Effects from Using Assembly in `pure` or `view` Functions\e[0m",
				description: "Using inline assembly within `pure` or `view` functions can lead to unintended side effects, potentially violating the expected behavior of these functions. Solidity enforces restrictions on state modifications in `pure` and `view` functions, but assembly can bypass these safeguards, leading to unexpected interactions with storage or execution context.",
				issues: "",
				recommendations: "Avoid using inline assembly in `pure` or `view` functions unless absolutely necessary. If assembly is required, thoroughly review the code to ensure no unintended state changes occur. Consider using Solidity's built-in functions instead of assembly whenever possible to maintain transparency and security."
			}
			issues_map << {
				key: :reverts_in_loops,
				title: "\e[32mEntire Transaction May Revert Due to `require` / `revert` Inside a Loop\e[0m",
				description: "Using `require` or `revert` inside a loop means that if any iteration fails, the entire transaction is reverted. This can be problematic in scenarios where partial progress should be preserved, such as batch processing or multi-step operations.",
				issues: "",
				recommendations: "It is advised to handle failed iterations individually instead of reverting the entire transaction."
			}
			issues_map << {
				key: :decimals_not_erc20,
				title: "\e[32m`decimals()` is not a part of the ERC-20 standard\e[0m",
				description: "The `decimals()` function is not a part of the ERC-20 standard and was added later as an optional extension. Some valid ERC20 tokens do not support this interface, so it is unsafe to blindly cast all tokens to this interface and then call this function.",
				issues: "",
				recommendations: "Ensure that the token supports the `decimals()` function before calling it."
			}
			issues_map << {
				key: :decimals_not_uint8,
				title: "\e[32m`decimals()` should be of type `uint8`\e[0m",
				description: "The `decimals()` function should be of type `uint8` to ensure compatibility with the ERC-20 standard.",
				issues: "",
				recommendations: "Ensure that the `decimals()` function is of type `uint8`."
			}
			issues_map << {
				key: :fallback_lacking_payable,
				title: "\e[32mFallback Lacking `payable`\e[0m",
				description: "The fallback function is not marked as `payable`, which means it cannot receive Ether. If the contract is expected to receive Ether, mark the fallback function as `payable`.",
				issues: "",
				recommendations: "Mark the fallback function as `payable` if it is expected to receive Ether."
			}
			issues_map << {
				key: :symbol_not_erc20,
				title: "\e[32m`symbol()` is not a part of the ERC-20 standard\e[0m",
				description: "The `symbol()` function is not part of the original ERC-20 standard and was introduced later as an optional extension. Some ERC-20 tokens do not implement this function, which can lead to contract failures if the function is called without checking for support. Blindly casting all tokens to an interface that includes `symbol()` may result in unexpected behavior.",
				issues: "",
				recommendations: "Verify that the token supports the `symbol()` function before calling it. This can be done using ERC-165's `supportsInterface` or by handling missing functions gracefully with a try-catch statement when interacting with untrusted tokens."
			}
			issues_map << {
				key: :hardcoded_year,
				title: "\e[32mInaccurate Year Duration Assumption\e[0m",
				description: "Assuming a year is exactly `365 days` in Solidity can lead to inaccuracies, as it does not account for leap years. Over time, these small discrepancies can accumulate, affecting contracts that rely on precise time-based calculations, such as vesting schedules or interest rate calculations.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use explicit time conversions:
				```solidity
				// Before
				uint256 year = 365 days;

				// Better alternative:
				uint256 year = 365.25 days; // Or use 1 years
				```
				RECOMMENDATIONS
			}

			# medium issues
			issues_map << {
				key: :single_point_of_control,
				title: "\e[33mCentralization Risk Due to Single Points of Control\e[0m",
				description: "Contracts with a single point of control pose centralization risks, making them vulnerable to malicious actions such as rug pulls or unauthorized upgrades. Contract owners must be trusted to act responsibly, but implementing security mechanisms can reduce these risks. To enhance security, consider using timelocks for administrative actions and multi-signature wallets (multi-sig) for privileged operations. These measures improve transparency and reduce the risk of a single entity having unchecked control.\n\nReference: [UK Court Ordered Oasis to Exploit Own Security Flaw to Recover 120k wETH Stolen in Wormhole Hack](https://medium.com/@observer1/uk-court-ordered-oasis-to-exploit-own-security-flaw-to-recover-120k-weth-stolen-in-wormhole-hack-fcadc439ca9d).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Implement timelock and multi-sig mechanisms for privileged operations.
				```solidity
				// Using OpenZeppelin's TimelockController
				import "@openzeppelin/contracts/governance/TimelockController.sol";
				
				// Or Gnosis Safe multi-sig
				import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :use_safemint,
				title: "\e[33mUse `_safeMint` Instead of `_mint` to Prevent NFT Loss\e[0m",
				description: "The `_mint()` function does not verify whether the recipient can receive ERC721 tokens, which can lead to lost or frozen NFTs if sent to an incompatible contract. Using `_safeMint()` ensures that the recipient is either an externally owned account (EOA) or a contract implementing `IERC721Receiver`, preventing this issue. This applies even when minting to `msg.sender`, as `msg.sender` might be a contract that does not support ERC721. Always use `_safeMint()` instead of `_mint()` to guarantee safe transfers.\n\nReferences: [EIP-721](https://eips.ethereum.org/EIPS/eip-721), [OpenZeppelin Warning ERC721.sol#L271](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/d4d8d2ed9798cc3383912a23b5e8d5cb602f7d4b/contracts/token/ERC721/ERC721.sol#L271), [Solmate `_safeMint`](https://github.com/transmissions11/solmate/blob/4eaf6b68202e36f67cab379768ac6be304c8ebde/src/tokens/ERC721.sol#L180), [OpenZeppelin `_safeMint`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L238-L250).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Replace `_mint` with `_safeMint` to ensure safe transfers.
				```solidity
				// Before
				_mint(to, tokenId);
				_mint(msg.sender, tokenId);
				
				// After
				_safeMint(to, tokenId, "");
				_safeMint(msg.sender, tokenId, "");
				
				// Recipient contract must implement:
				function onERC721Received(address, address, uint256, bytes memory) 
					public pure returns (bytes4) {
					return this.onERC721Received.selector;
				}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :use_of_cl_lastanswer,
				title: "\e[33mReplace `latestAnswer` with `latestRoundData()` for Reliable Price Feeds\e[0m",
				description: "The `latestAnswer` function is deprecated and does not return an error if no valid price is available, instead defaulting to `0`. This can lead to inaccurate price feeds or potential denial-of-service issues. To ensure price accuracy and contract reliability, use `latestRoundData()` and include validation checks for stale or invalid prices.\n\nReferences: [Chainlink API Reference - latestAnswer](https://docs.chain.link/data-feeds/api-reference#latestanswer), [latestRoundData() Documentation](https://docs.chain.link/data-feeds/api-reference#latestrounddata).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use latestRoundData() with validation checks
				```solidity
				(, int256 price,, uint256 updatedAt,) = 
					chainlinkFeed.latestRoundData();
				
				require(updatedAt >= block.timestamp - 1 hours, "Stale price");
				require(price > 0, "Invalid price");
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :solmate_not_safe,
				title: "\e[33mUse OpenZeppelin's `SafeERC20` Instead of `SafeTransferLib.sol` for Safer Transfers\e[0m",
				description: "Solmate's `SafeTransferLib.sol` does not verify whether a token address is a valid contract, leaving this responsibility to the caller. This increases the risk of honeypot attacks, where a malicious contract can trap funds. To enhance security, use OpenZeppelin's `SafeERC20`, which includes additional safety checks to prevent interacting with non-existent token contracts.\n\nReferences: [Solmate's SafeTransferLib.sol](https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol#L9), [Qubit Finance Hack - January 2022](https://www.halborn.com/blog/post/explained-the-qubit-hack-january-2022), [OpenZeppelin SafeERC20](https://docs.openzeppelin.com/contracts/2.x/api/token/erc20#SafeERC20).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use OpenZeppelin's SafeERC20 instead
				```solidity
				// Before
				import "solmate/utils/SafeTransferLib.sol";
				SafeTransferLib.safeTransferFrom(token, from, to, amount);
				
				// After
				import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
				SafeERC20.safeTransferFrom(IERC20(token), from, to, amount);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :nested_loop,
				title: "\e[33mAvoid Nested Loops to Prevent Denial of Service\e[0m",
				description: "Nested loops in Solidity can cause an exponential increase in gas consumption, potentially leading to transaction failures and denial of service. This can compromise the reliability and scalability of the protocol. To mitigate this issue, avoid nested loops whenever possible or implement pagination to process data in smaller batches.",
				issues: "",
				recommendations: "Avoid nested loops or implement pagination"
			}
			issues_map << {
				key: :unchecked_recover,
				title: "\e[33mValidate `ECDSA.recover` Output to Prevent Unintended Behavior\e[0m",
				description: "The `ECDSA.recover` function returns `address(0)` if the provided signature is invalid. If this output is not checked, it can lead to unintended behavior, such as unauthorized access or incorrect validation. To ensure security, always validate the recovered address and revert if it is `address(0)`. Additionally, compare the recovered address with the expected signer to prevent unauthorized actions.\n\nReference: [OpenZeppelin ECDSA.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v2.5.1/contracts/cryptography/ECDSA.sol#L28).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Validate recovered address
				```solidity
				address signer = ecrecover(hash, v, r, s);
				require(signer != address(0), "Invalid signature");
				require(signer == expectedSigner, "Unauthorized");
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :unchecked_transfer_transferfrom,
				title: "\e[33mCheck the Return Value of `transfer` and `transferFrom` to Prevent Silent Failures\e[0m",
				description: "Not all ERC20 token implementations revert on failure—some return `false` instead. If the return value of `transfer` or `transferFrom` is not checked, failed transfers might go unnoticed, leading to unintended behavior. To ensure safe transfers, use OpenZeppelin's `SafeERC20`, which correctly handles failures, or explicitly check the return value and revert if the transfer fails.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use SafeERC20 or check return values
				```solidity
				// With SafeERC20
				SafeERC20.safeTransfer(token, to, amount);
				
				// Manual check
				bool success = token.transfer(to, amount);
				require(success, "Transfer failed");
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :use_of_blocknumber,
				title: "\e[33mAvoid Using `block.number` for Time Calculations Across EVM Chains\e[0m",
				description: "The interpretation of `block.number` varies across Layer 2 networks. On Optimism, it represents the L2 block number, while on Arbitrum, it reflects the L1 block number. These inconsistencies can cause logic errors in contracts that rely on `block.number` for time-sensitive operations. To ensure consistency across different chains, use `block.timestamp` instead of `block.number` for time-based calculations.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use timestamp-based durations instead
				```solidity
				// Before
				uint256 deadline = block.number + 100;
				
				// After (assuming 15s blocks)
				uint256 deadline = block.timestamp + 25 minutes; 
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :stale_check_missing,
				title: "\e[33mValidate Oracle Data Freshness to Prevent Stale Price Usage\e[0m",
				description: "Fetching price or data values from oracles without checking their timestamps can lead to outdated or incorrect values being used in contract operations. If an oracle is down, unresponsive, or delayed, it may return stale data, leading to vulnerabilities or incorrect calculations. To prevent this, always implement a staleness check by ensuring the data's timestamp is within an acceptable threshold (e.g., 1 hour).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Add staleness checks for oracle data
				```solidity
				(, int256 price,, uint256 updatedAt,) = 
					priceFeed.latestRoundData();
				
				require(
					updatedAt >= block.timestamp - 2 hours,
					"Stale price data"
				);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :tx_origin_usage,
				title: "\e[33mUse of `tx.origin` for Authorization\e[0m",
				description: "Using `tx.origin` instead of `msg.sender` for access control exposes the contract to phishing attacks. Malicious contracts can trick users into executing transactions that bypass security checks. To prevent this, always use `msg.sender` for validating authorized callers.\n\nReference: [Solidity Docs: tx.origin](https://docs.soliditylang.org/en/latest/security-considerations.html#tx-origin).",
				issues: "",
				recommendations: "Replace `tx.origin` with `msg.sender`"
			}
			issues_map << {
				key: :gas_griefing,
				title: "\e[33mUse Bounded Gas for External Calls to Prevent Gas Griefing Attacks\e[0m",
				description: "Forwarding all available gas in external calls (e.g., `call{gas: ...}`) can allow attackers to trigger out-of-gas failures, leading to denial-of-service vulnerabilities. To improve reliability, always set a bounded gas limit (e.g., `gas: 100000`) when making external calls.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use bounded gas for external calls
				```solidity
				// Before
				(bool success,) = to.call{value: amount}("");
				
				// After
				(bool success,) = to.call{value: amount, gas: 100000}("");
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :insecure_randomness,
				title: "\e[33mAvoid Using `blockhash` for Randomness to Prevent Manipulation\e[0m",
				description: "Using `blockhash` for randomness is insecure because miners can influence the outcome by selectively mining blocks. This makes it unsuitable for applications requiring fair and unpredictable randomness. To ensure secure randomness, use decentralized oracles such as Chainlink VRF, which provides verifiable and tamper-proof random values.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use Chainlink VRF for randomness
				```solidity
				import "@chainlink/contracts/src/v0.8/VRFConsumerBase.sol";
				
				function requestRandomness() external {
					bytes32 requestId = requestRandomness(keyHash, fee);
				}
				
				function fulfillRandomness(bytes32, uint256 randomness) internal override {
					// Use secure random number
				}
				```
				RECOMMENDATIONS
			}

			# high issues
			issues_map << {
				key: :delegatecall_in_loop_payable,
				title: "\e[31mUse of `delegatecall` Inside Loops in Payable Function\e[0m",
				description: "Using `delegatecall` within a loop in a payable function can cause issues where each call retains the `msg.value` from the initial transaction. This can lead to unintended fund transfers and vulnerabilities. If `delegatecall` inside a loop is unavoidable, ensure that no `msg.value` is forwarded within loops, implement strict access controls, and use reentrancy guards to prevent attacks.\n\nReference: [\"Two Rights Might Make A Wrong\" by samczsun](https://www.paradigm.xyz/2021/08/two-rights-might-make-a-wrong).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Avoid using `delegatecall` inside loops. If unavoidable:
				1. Ensure no `msg.value` is forwarded in loops
				2. Use strict access controls
				3. Implement reentrancy guards
				4. Explicitly handle ether transfers outside of loops to prevent unintended forwarding
			
				```solidity
				// Add reentrancy guard
				bool private locked;
				modifier noReentrant() {
					require(!locked, "Reentrant call");
					locked = true;
					_;
					locked = false;
				}
			
				function safeDelegatecall(address target, bytes memory data) 
					external payable noReentrant {
					require(msg.value == 0, "Cannot forward ETH in delegatecall loop");
			
					(bool success,) = target.delegatecall(data);
					require(success, "Delegatecall failed");
				}
			
				function withdraw() external {
					payable(msg.sender).transfer(address(this).balance);
				}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :arbitrary_from_in_transferFrom,
				title: "\e[31mArbitrary `from` Address in `transferFrom` / `safeTransferFrom`\e[0m",
				description: "Allowing any `from` address in `transferFrom` or `safeTransferFrom` can lead to unintended fund transfers if an attacker gains approval to move tokens on behalf of another address. Ensuring that `msg.sender` is either the `from` address or an approved operator prevents unauthorized token transfers. Using OpenZeppelin's `SafeERC20` implementation further enhances security by handling transfer failures properly.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Validate that `msg.sender` is either:
				- The `from` address, or
				- An approved operator
				
				```solidity
				function transferFrom(address from, address to, uint256 amount) public {
					require(
						from == msg.sender || allowance[from][msg.sender] >= amount,
						"Unauthorized"
					);
					_transfer(from, to, amount);
				}
				
				// Or use OpenZeppelin's implementation
				import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
				SafeERC20.safeTransferFrom(token, msg.sender, to, amount);
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :msgvalue_in_loop,
				title: "\e[31mAvoid Using `msg.value` Inside Loops to Prevent Logic Errors\e[0m",
				description: "Reusing `msg.value` inside a loop can cause unintended behavior since the same value persists across iterations. This can break protocol logic, especially in cases involving multiple recipients or dynamic calculations. To ensure correct value distribution, track the remaining ETH explicitly and deduct the portion sent in each iteration.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Track remaining ETH explicitly:
				
				```solidity
				uint256 remainingValue = msg.value;
				for (uint i = 0; i < iterations; i++) {
					uint256 portion = remainingValue / (iterations - i);
					(bool success,) = payable(recipient).call{value: portion}("");
					require(success, "Transfer failed");
					remainingValue -= portion;
				}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :unsafe_casting,
				title: "\e[31mUnsafe type casting\e[0m",
				description: "Casting from a larger type to a smaller type without proper validation can cause truncation, leading to unexpected behavior. If the value exceeds the target type's range, it may result in overflow or underflow, potentially introducing critical vulnerabilities. To prevent this, ensure that all type conversions check for validity before execution. Using OpenZeppelin's `SafeCast` library helps mitigate these risks by reverting on invalid casts.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use OpenZeppelin's SafeCast library:
				
				```solidity
				import "@openzeppelin/contracts/utils/math/SafeCast.sol";
				
				uint256 largeValue = 500;
				uint32 smallValue = SafeCast.toUint32(largeValue); // Reverts if overflow
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :uninitialized_storage,
				title: "\e[31mUninitialized Storage Pointers\e[0m",
				description: "Uninitialized storage variables may reference unintended storage slots, leading to data corruption or potential exploits. When a storage pointer is declared but not explicitly assigned, it can point to an arbitrary location in contract storage, causing unpredictable behavior. To prevent this, always initialize storage variables explicitly before use.\n\nReference: [Solidity Docs: Storage Pointers](https://docs.soliditylang.org/en/latest/types.html#data-location).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Always initialize storage variables explicitly:
				
				```solidity
				// Explicit initialization
				struct Data {
					uint256 value;
				}
				
				function store() public {
					Data storage d; // INCORRECT
					
					Data storage d = data[msg.sender]; // CORRECT
					d.value = 100;
				}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :get_dy_underlying_flash_loan,
				title: "\e[31mPrice Manipulation Risk Due to Flash Loan Vulnerability in `get_dy_underlying()`\e[0m",
				description: "Using `get_dy_underlying()` as a price oracle is unsafe because it can be manipulated through flash loans, leading to inaccurate pricing and potential exploits. Since flash loans allow attackers to temporarily inflate or deflate asset values, relying on this function for pricing can expose contracts to severe financial risks. To mitigate this, use a secure oracle like Chainlink, which provides tamper-resistant pricing and includes staleness checks to prevent the use of outdated data.\n\nReference: [Chainlink Data Feeds](https://docs.chain.link/data-feeds/).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use Chainlink oracles with staleness checks:
				
				```solidity
				// Replace vulnerable code
				uint256 price = curvePool.get_dy_underlying(...);
				
				// With secure oracle
				(uint80 roundID, int256 price,, uint256 updatedAt,) = 
					chainlinkFeed.latestRoundData();
				require(updatedAt >= block.timestamp - 1 hours, "Stale price");
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :wsteth_price_steth,
				title: "\e[31mIncorrect Price Calculation When Converting Between `wstETH` and `stETH`\e[0m",
				description: "Incorrect price calculation between wstETH and stETH. Multiply `price` by `WstETH.stEthPerToken()` to convert to ETH units.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Multiply by conversion rate:
				
				```solidity
				// Before (incorrect)
				uint256 ethAmount = price * wstETHAmount;
				
				// After (correct)
				uint256 stEthPerToken = IWstETH(wstETH).stEthPerToken();
				uint256 ethAmount = price * wstETHAmount * stEthPerToken / 1e18;
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :yul_return_usage,
				title: "\e[31mUnintended Execution Flow Due to `return` Statement in Yul Assembly\e[0m",
				description: "Using `return` in Yul assembly immediately halts execution, potentially skipping critical operations such as cleanup or state updates. This can introduce unexpected behavior or leave the contract in an inconsistent state. To ensure safe execution, always complete necessary operations before returning from an assembly block.\n\nReference: [Inline Assembly | Solidity Docs](https://docs.soliditylang.org/en/latest/assembly.html#conventions-in-solidity).",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Avoid early returns in assembly blocks. Ensure all cleanup operations complete:
				
				```solidity
				assembly {
					let result := delegatecall(...)
					// Perform all necessary operations
					switch result
					case 0 { revert(0, 0) }
					default { return(0, 0) } // Safe if all ops complete
				}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :rtlo_character,
				title: "\e[31mRTLO character detected\e[0m",
				description: "The right-to-left override (RTLO) character (U+202E) can be used to visually obfuscate text, potentially misleading users or causing confusion in string representation. This could introduce risks in contract interactions or auditing processes. To mitigate this, ensure all strings and comments are free of RTLO characters. Additionally, implement a pre-commit hook to automatically detect RTLO characters and prevent their inclusion in the codebase.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				1. Remove RTLO characters from all strings/comments
				2. Add pre-commit hook to detect RTLO:
				```bash
				# .pre-commit-config.yaml
				- repo: https://github.com/pre-commit/pre-commit-hooks
				rev: v4.4.0
				hooks:
					- id: check-byte-order-marker
					- id: check-merge-conflict
					- id: check-yaml
					- id: detect-private-key
					- id: end-of-file-fixer
					- id: mixed-line-ending
					- id: trailing-whitespace
					- id: check-ast
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :multiple_retryable_calls,
				title: "\e[31mRisk of Inconsistent Behavior Due to Multiple Retryable Calls\e[0m",
				description: "Using multiple retryable ticket calls within a single function can lead to them being executed out of order, causing inconsistencies and unintended behavior. This can be mitigated by ensuring that each retryable call is associated with a unique, sequential identifier or nonce. To ensure correct execution order, use atomic transactions or sequence numbers to track and validate each retryable call.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Use atomic transactions or sequence numbers:
				
				```solidity
				uint256 public nonce;
				
				function executeWithRetry() external {
					uint256 currentNonce = nonce++;
					// Include nonce in retryable data
					inbox.createRetryableTicket({
						data: abi.encode(currentNonce, ...)
					});
				}
				```
				RECOMMENDATIONS
			}
			issues_map << {
				key: :contract_locks_ether,
				title: "\e[31mLocked Ether Due to Missing Withdraw Function\e[0m",
				description: "When a contract includes payable functions but lacks a method to withdraw Ether, funds can become locked, making them inaccessible to the contract owner or other authorized parties. This can result in a loss of control over the funds. To fix this, implement a withdraw function that allows Ether to be safely transferred out of the contract. Ensure proper access control to prevent unauthorized withdrawals.",
				issues: "",
				recommendations: <<~RECOMMENDATIONS
				Add withdraw function with access control:
				
				```solidity
				function withdrawETH(address payable to) external onlyOwner {
					uint256 balance = address(this).balance;
					(bool sent,) = to.call{value: balance}("");
					require(sent, "Failed to send Ether");
				}
				
				// Or use OpenZeppelin's Escrow pattern
				import "@openzeppelin/contracts/utils/Escrow.sol";
				```
				RECOMMENDATIONS
			}

			process_files_in_parallel(sol_files, issues_map)

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

			create_report(issues_map, sol_files)

			# Track Analysis execution
			end_time = Time.now
			execution_time = end_time - start_time			
			puts "Analysis executed in \e[94m#{execution_time}\e[0m seconds"

		else
			puts "\n[\e[31m+\e[0m] ERROR: No solidity file found"
		end

	else
		puts "\n[\e[31m+\e[0m] ERROR: No directory found"
	end

rescue Exception => e
	puts "\n[\e[31m+\e[0m] ERROR: #{e.message}"
	puts e.backtrace.join("\n")
end
