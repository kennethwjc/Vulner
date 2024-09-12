#!/bin/bash

#~ Function to get the network from user input in CIDR format
get_network() {
	#~ Prompt the user to enter a network address to scan and store the input in the variable 'network'
    read -p "Enter the network to scan (e.g., 192.168.1.0/24): " network
}

#~ Function to determine the filepath for saving results
get_filepath() {
	#~ Prompt the user to decide whether to use the default file path for saving results (yes/no)
    read -p "Use default file path for saving results? (yes/no): " use_default
    #~ Check if the user wants to use the default path
    if [[ "$use_default" == "yes" ]]; then
		#~ Set filepath variable to the default location on the Desktop
        filepath="$HOME/Desktop/vulner_results.txt"
    else
		#~ Enter a loop to repeatedly ask for a valid directory path until one is provided
        while true; do
			#~ Prompt the user to enter a custom directory path to save the scan results
            read -p "Enter the directory path to save the scan results: " custom_path
            #~ Check if the entered path is a valid directory with the -d flag
            if [[ -d "$custom_path" ]]; then
				#~ Set the filepath variable to the specified custom path with the filename
                filepath="$custom_path/vulner_results.txt"
                #~ Exit the loop as a valid directory path has been provided
                break
            else
				#~ Inform the user that the entered path is invalid and prompt again
                echo "The path '$custom_path' does not exist. Please enter a valid directory path."
            fi
        done
    fi
}

#~ Function to perform an nmap scan $1 being either basic or full
perform_nmap_scan() {
    echo "Performing $1 scan on $network..."   
    #~ Run nmap command with service version detection and saving into "nmap_output" variable
    nmap_output=$(nmap -sV "$network")
    #~ Save nmap scan results to the specified file path
    echo "$nmap_output" > "$filepath"
    #~ Let user know that the nmap scan is done
    echo "$1 network scan complete. Results saved to $filepath."
}

#~ Function to list discovered services and perform brute force attacks
list_services_and_bruteforce() {
    #~ Determine the current directory
    current_directory=$(pwd)
    
    #~ Prompt the user for the username and password file names
    read -p "Enter the name of the username file (located in the current directory): " username_file
    read -p "Enter the name of the password file (located in the current directory): " password_file

    #~ Reassigning variables to the user and password files
    username_list="$current_directory/$username_file"
    password_list="$current_directory/$password_file"

    #~ Check if the files exist in the current directory
    if [[ ! -f "$username_list" ]]; then
        echo "Username file '$username_file' not found in the current directory."
        exit 1
    fi

    if [[ ! -f "$password_list" ]]; then
        echo "Password file '$password_file' not found in the current directory."
        exit 1
    fi

    #~ Extract hosts with relevant services from nmap output
    #~ Initialize an empty array to store hosts and services found by the nmap scan.
    services_hosts=()
    #~ Start a while loop to read each line of the nmap output.
    while read -r line; do
		#~ Check if the line contains the string "Nmap scan report for".
        if [[ "$line" == "Nmap scan report for"* ]]; then
			#~ Extract the host name or IP address from the line.
			#~ Use awk to print the last field ($NF) and tr to remove parentheses.
            host=$(echo "$line" | awk '{print $NF}' | tr -d '()')
        #~ Check if the line contains the word "open", indicating an open port.
        elif [[ "$line" == *"open"* ]]; then
			#~ Use awk with -F to split by '/' and print the first field (port number)
            port=$(echo "$line" | awk -F/ '{print $1}')
            #~ Extract the service name from the line.
            service=$(echo "$line" | awk '{print $3}')
            #~ Check if the service is one of the specified types (ftp, ssh, rdp, telnet)
            if [[ "$service" == "ftp" || "$service" == "ssh" || "$service" == "ms-wbt-server" || "$service" == "telnet" ]]; then
                #~ Append the host, port, and service to the services_hosts array.
                services_hosts+=("$host:$port ($service)")
            fi
        fi
	#~ Pipe the filtered nmap output to the while loop.
    done <<< "$(echo "$nmap_output" | grep -E 'Nmap scan report for|open')"
	
	#~ Check if the services_hosts array is empty if no services found
    if [ ${#services_hosts[@]} -eq 0 ]; then
        echo "No relevant services found in the scan."
		#~ Exit the function or loop if no services are found.
        return
    fi

    #~ Print message to indicate that the list of available hosts
    echo "Available hosts with relevant services:"
    #~ Iterate over the indices of the services_hosts array
    for i in "${!services_hosts[@]}"; do
        #~ Print the index and the corresponding service host information from the array
        echo "[$i] ${services_hosts[i]}"
    done

    #~ Select IP address and service for brute force
    read -p "Select the index of the IP to brute force: " index
    #~ Retrieve the selected entry from the services_hosts list
    selected_entry="${services_hosts[$index]}"

    #~ Split the 'selected_entry' into 'host_info' and 'service_info' by spaces, where 'host_info' contains 'host:port' and 'service_info' contains '(service)'.
    IFS=' ' read -r host_info service_info <<< "$selected_entry"
    #~ Split 'host_info' into 'host' and 'port' by colons, after removing any trailing '(service)' text.
    IFS=':' read -r host port <<< "${host_info% (*}"
    #~ Remove parentheses from 'service_info' to isolate the service name.
    service="${service_info//[()]/}"

	#~ Print message indicating the start of the brute force attack for the specified host, port, and service
    echo "Starting brute force on $host:$port ($service)"
    #~ Begin case statement to handle different types of services
    case $service in
        #~ If service is FTP
        ftp)
            hydra -L "$username_list" -P "$password_list" "ftp://$host:$port" >> "$filepath"
            ;;
        #~ If service is SSH
        ssh)
            hydra -L "$username_list" -P "$password_list" "ssh://$host:$port" >> "$filepath"
            ;;
        #~ If service is Telnet
        telnet)
            hydra -L "$username_list" -P "$password_list" "$host" telnet >> "$filepath"
            ;;
        #~ If service is RDP
        ms-wbt-server)
            hydra -L "$username_list" -P "$password_list" "rdp://$host:$port" >> "$filepath"
            ;;
        #~ If none of the above services match
        *)
            echo "Unknown service type."
            ;;
    esac
    
	#~ Check the exit status of Hydra command and print whether the brute force was successful or not
    if [[ $? -eq 0 ]]; then
        echo "Brute force successful for $service on $host:$port."
    else
        echo "Brute force failed for $service on $host:$port."
    fi
    
	#~ Let user know if bruteforce process is complete
    echo "Brute force complete."
}

#~ Function to perform vulnerability checking with searchsploit
check_vulnerabilities() {
    echo "Checking for vulnerabilities based on nmap scan results..."
    
    #~ Define the directory for saving the searchsploit results
    results_dir="${filepath%/*}/searchsploit_results"
    
    #~ Create the directory if it does not exist
    mkdir -p "$results_dir"

    #~ Define the combined result file
    combined_result_file="$results_dir/combined_searchsploit_results.txt"
    
    #~ Clear the combined result file if it exists
    > "$combined_result_file"

    #~ Extract service names and versions from nmap output
    while read -r line; do
        if [[ "$line" == *"open"* ]]; then
            #~ Extract the service name from the line
            service=$(echo "$line" | awk '{print $3}')
            #~ Extract the version number from the line
            version=$(echo "$line" | awk '{print $4, $5}')

            #~ Check if the service name and version are not empty
            if [[ -n "$service" && -n "$version" ]]; then
                echo "Searching for vulnerabilities for $service version $version..."
                
                echo $service $version >> $combined_result_file
                
                #~ Run searchsploit with the service name and version
                searchsploit "$service $version" >> "$combined_result_file"
                
                #~ Add a separator for readability between results
                echo -e "\n===================================\n" >> "$combined_result_file"
            fi
        fi
    done <<< "$(echo "$nmap_output" | grep -E 'open')"

    echo "Vulnerability check complete. Combined results saved in $combined_result_file."
}


#~ Main function
main() {
	#~ Call function to get the network to scan from user input
    get_network
    #~ Call function to get the file path for saving results from user input
    get_filepath
    
    #~ Prompt the user to choose between 'basic' or 'full' scan types
    read -p "Choose scan type (basic/full): " scan_type
    #~ Convert the user input to lowercase
    scan_type=$(echo "$scan_type" | tr '[:upper:]' '[:lower:]')

	#~ Check if the selected scan type is either 'basic' or 'full'
    if [[ "$scan_type" == "basic" || "$scan_type" == "full" ]]; then
        #~ Perform the nmap scan with the selected scan type (function)
        perform_nmap_scan "$scan_type"
        #~ List services found and perform brute force attacks on them (function)
        list_services_and_bruteforce
        #~ If the scan type is 'full', also check for vulnerabilities (function)
        if [[ "$scan_type" == "full" ]]; then
            check_vulnerabilities
        fi
        
        #~ Prompt the user if they would like to zip up the results files
        read -p "Would you like to zip up the results files? (yes/no): " zip_choice
        zip_choice=$(echo "$zip_choice" | tr '[:upper:]' '[:lower:]')

        if [[ "$zip_choice" == "yes" ]]; then
            #~ Define the zip file name
            zip_file="${filepath%/*}/scan_results.zip"
            #~ Zip the file
            zip -j "$zip_file" "$filepath" "${filepath%/*}/searchsploit_results/combined_searchsploit_results.txt"
            echo "Results have been zipped into $zip_file."
        else
            echo "Results were not zipped."
        fi
        
    else
        echo "Invalid scan type selected."
        exit 1
    fi
}


#~ Run main function to start the script
main
