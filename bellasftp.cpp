// Naive learning-to-code sftp server with bella render integration

#define WITH_SERVER

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/sftp.h>
#include <libssh/sftpserver.h>

#include <iostream>
#include <cstring>

#include <curl/curl.h> // for curl apt-get install -y  libcurl4-openssl-dev

#include <stdio.h>
#include <regex>
//#include <sstream>
#include <fstream>
#include <filesystem> // For path manipulation (C++17 and later)


//#include <fcntl.h>  // Include for O_WRONLY, O_CREAT, O_TRUNC
#include <sys/stat.h> // For permissions (0644)
#include <unistd.h> //for close()

#include <string>
#include <sys/types.h>
#include <cerrno> // For errno (error number)
#include <vector>

const char* USERNAME = "bella"; // Replace with your desired username
const char* PASSWORD = "render"; // Replace with your desired password

const char* BINDADDR = "0.0.0.0";
const char* BINDPORT = "2225";
const char* HOSTKEY = "ssh-rsa";

// Write function used by curl (modified to use std::ostream)
size_t write_data(void* buffer, size_t size, size_t nmemb, std::ostream* stream) {
    size_t written = size * nmemb;
    if (stream->write(static_cast<char*>(buffer), written)) {
        return written; // Return the number of bytes written
    }
    return 0; // Indicate an error
}

enum sessionType {
  PTY,
  SHELL,
  SFTP
};

// Here we handle both ssh and possible sftp subsystem
// [TODO] split out sftp stuff
void handle_client(ssh_session client_session) {
    ssh_message message; // bridge class to go from developer friendly to efficient wire format
    while ((message = ssh_message_get(client_session))) { // client handler session loop post authentication
        
        // blocking function until message received or timeout
        /*Channel Handling: SSH servers need to be able to handle different types of channel requests. 
        This if statement allows the server to specifically identify and handle requests for session channels.
        Session channels are the most common type of channel. 
        They are used for interactive shell sessions, executing commands, and establishing other subsystems like SFTP.
        */

        sessionType current_type = PTY; //defsult
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
            ssh_channel channel = ssh_message_channel_request_open_reply_accept(message); // Accept a channel
            ssh_message_free(message); // Free any memory used by ssh_message

            //TOPLEVEL messaging
            // naive implementation of ssh and sftp subsystem handshaking protocols
            // specific support for only ssh via pty and sftp put and get
            // message passing 
            while ((message = ssh_message_get(client_session))!= nullptr) { // ssh messaging outer loop 
                if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) { // is channel request?
                    if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY) { // is pseudo-terminal (PTY)?
                        std::cout << "pty" << std::endl;
                        ssh_message_channel_request_reply_success(message); // Approve
                        ssh_message_free(message);  // Free the message (it's no longer needed)
                        break; // Exit loop to start interacting with the client
                    } else if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SUBSYSTEM) { // Check for SFTP request
                        current_type = SFTP;
                        ssh_message_channel_request_reply_success(message); // Approve
                        ssh_message_free(message);  // Free the message (it's no longer needed)

                        // Now you have the channel, you can create the sftp session
                        sftp_session sftp = sftp_server_new(client_session, channel);    
                        if (sftp == NULL) {
                            fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(client_session)); 
                            return; 
                        }

                        std::cout  << "sftp_server_new"  << "\n";
                        sftp_client_message message;
                        
		                int rc;

                        if (sftp == NULL) {
                            std::cout << "failed to create sftp session" << std::endl;
                            return; 
                        }

                        rc = sftp_server_init(sftp);
                        std::cout  << "SFTP sftp_server_init"  << "\n";
                        if (rc != 0) {
                            std::cout << "failed to initialize sftp session" << std::endl;
                            std::cout << sftp_get_error(sftp) << std::endl;
                        }

                        uint32_t flags_to_check = SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC;


                        // sftp message outer loop
                        while ((message = sftp_get_client_message(sftp))!= nullptr) { 
                            uint8_t sftp_message_type = sftp_client_message_get_type(message); //type is opcode
                            uint32_t message_flags = sftp_client_message_get_flags(message); //type is opcode
                            std::cout << "flags:" <<  message_flags << std::endl;
                            //std::cout << "message id:" <<  message->id << std::endl;

                            switch (sftp_message_type) {

                                // Handle "get orange-juice.bsz"
                                // 1. Client->SSH_FXP_LSTAT test symbolic link
                                // 2. Server->
                                // 3. Client->SSH_FXP_STAT test file
                                case SSH_FXP_LSTAT: { // a get orange-juice.bsz starts with an _LSTAT request
                                    const char* path = sftp_client_message_get_filename(message);
                                    std::string filename = sftp_client_message_get_filename(message);
                                    std::cout << "Client lstat" << path << std::endl;
                                    
                                    std::string bella_file = "/tmp/oj.bsz"; //hardcoded
                                    std::ifstream binaryInputFile(bella_file, std::ios::binary);
                                    if (binaryInputFile.is_open()) {
                                        std::cout << "Success opened file '" << bella_file << "' for binary reading." << std::endl;
                                    } else {
                                        std::cerr << "Error opening file '" << bella_file << "' for binary reading." << std::endl;
                                    }           
                                    struct stat file_stat;
                                    if (lstat(bella_file.c_str(), &file_stat) == 0) {

                                        //File attributes must be sent to client
                                        sftp_attributes my_sftp_attrib = (sftp_attributes)malloc(sizeof(struct sftp_attributes_struct)); // Allocate memory using malloc
                                        if (my_sftp_attrib == NULL) { // Check for allocation failure!
                                            std::cerr << "Memory allocation failed for sftp_attributes." << std::endl;
                                            return; // Exit function on allocation error
                                        }
                                        memset(my_sftp_attrib, 0, sizeof(struct sftp_attributes_struct)); // Initialize to 0
                                        my_sftp_attrib->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME | SSH_FILEXFER_ATTR_UIDGID;
                                        my_sftp_attrib->size = file_stat.st_size;
                                        my_sftp_attrib->uid = file_stat.st_uid;
                                        my_sftp_attrib->gid = file_stat.st_gid;
                                        my_sftp_attrib->permissions = file_stat.st_mode;
                                        my_sftp_attrib->atime = file_stat.st_atime;
                                        my_sftp_attrib->mtime = file_stat.st_mtime;
                                        sftp_reply_attr(message, my_sftp_attrib ); //I processed this data please send more
                                        free(my_sftp_attrib); // free memory

                                        //[TODO] rename message_data message
                                        sftp_client_message message_data;

                                        // Inner loop to handle
                                        while ((message_data = sftp_get_client_message(sftp))!= nullptr) { // outer loop for client kill
                                            uint8_t sftp_message_type = sftp_client_message_get_type(message_data); 
                                            switch (sftp_message_type) {
                                                case SSH_FXP_STAT: { 
                                                    std::cerr << "  stat: " <<  std::endl;
                                                    sftp_reply_attr(message_data, my_sftp_attrib ); //I processed this data please send more
                                                    break;
                                                }
                                                case SSH_FXP_OPEN: { 
                                                    //const char* bella_file = "/tmp/oj.bsz";
                                                    std::cerr << "  open: " <<  std::endl;
                                                    const char *my_string_data = "Hello, ssh_string!";
                                                    size_t data_len = strlen(my_string_data);
                                                    ssh_string my_handle = NULL;
                                                    my_handle = ssh_string_from_char("Banner Example\n"); 
                                                    sftp_reply_handle(message_data, my_handle); //I processed this data please send more
                                                    
                                                    std::cerr << "  read: " <<  std::endl;
                                                    const size_t chunk_size = 32768;
                                                    size_t total_bytes_read = 0;
                                                    std::vector<char> buffer1(chunk_size); // Buffer to hold each chunk

                                                    sftp_client_message message_data2;
                                                    while ((message_data2 = sftp_get_client_message(sftp))!= nullptr) { // outer loop for client kill
                                                        uint8_t sftp_message_type2 = sftp_client_message_get_type(message_data2); 
                                                        switch (sftp_message_type2) {
                                                            case SSH_FXP_READ: { 

                                                                binaryInputFile.read(buffer1.data(), chunk_size);
                                                                std::streamsize bytes_read_in_chunk = binaryInputFile.gcount(); // Actual bytes read

                                                                if (bytes_read_in_chunk > 0) {
                                                                    // Process the chunk of data you just read (bytes_read_in_chunk bytes in buffer)
                                                                    std::cout << "Read chunk of " << bytes_read_in_chunk << " bytes." << std::endl;
                                                                    
                                                                    /*std::cout << "First few bytes: ";
                                                                    for (int i = 0; i < std::min((int)bytes_read_in_chunk, 10); ++i) {
                                                                        std::cout << static_cast<int>(buffer1[i]) << " "; // Print as integers
                                                                    }
                                                                    std::cout << std::endl;
                                                                    */

                                                                    sftp_reply_data(message_data2, buffer1.data() , bytes_read_in_chunk);
                                                                    total_bytes_read += bytes_read_in_chunk;
                                                                } else { // No bytes read in this chunk. Check why:
                                                                    if (binaryInputFile.eof()) {
                                                                        std::cout << "Reached end of file." << std::endl;
                                                                        return; // End of file reached, exit handle_client
                                                                    } else if (binaryInputFile.fail() || binaryInputFile.bad()) {
                                                                        std::cerr << "Error during file read." << std::endl;
                                                                        return; // Error occurred, exit loop
                                                                        break; // using return for now to exit handler
                                                                    } else {
                                                                        // Should not normally reach here if gcount() is 0 and not EOF or error,
                                                                        // but as a safety net, break to avoid infinite loop.
                                                                        return; // Error occurred, exit loop
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                    } else { // lstat failure, these are bypassed currently as bella_file is hardcoded
                                        int status_code;
                                        if (errno == ENOENT) {
                                            status_code = SSH_FX_NO_SUCH_FILE;
                                            std::cerr << "  File not found: " << filename << std::endl;
                                        } else if (errno == EACCES) {
                                            status_code = SSH_FX_PERMISSION_DENIED;
                                            std::cerr << "  Permission denied to access: " << filename << std::endl;
                                        } else {
                                            status_code = SSH_FX_FAILURE; // Generic failure
                                            std::cerr << "  Error getting file status for: " << filename << " (errno: " << errno << ")" << std::endl;
                                        }
                                        sftp_reply_status(message, SSH_FX_FAILURE, "FAIL" );
                                    }
                                }

                                // Handles "put orange-juice.bsz"
                                case SSH_FXP_OPEN: { 
                                    if ((message_flags & flags_to_check ) == flags_to_check) {
                                        std::cout << "  SSH_FXF_WRITE flag is SET (Client intends to upload)." << std::endl;
                                    }
                                    if ((message_flags & SSH_FXF_APPEND) != 0) {
                                        std::cout << "  SSH_FXF_APPEND flag is SET (Client intends to upload)." << std::endl;
                                    }
                                    if ((message_flags & SSH_FXF_READ) != 0) {
                                        std::cout << "  SSH_FXF_READ flag is SET (Client intends to read/download)." << std::endl;
                                    }

                                    const char* fooname = "/tmp/orange-juice.bsz";
                                    const char* path = sftp_client_message_get_filename(message);
                                    std::cout << "Client sent path" << path << std::endl;
                                    //int access_type = O_WRONLY | O_CREAT | O_TRUNC;

                                    std::ofstream binaryOutputFile(fooname, std::ios::binary);
                                    if (!binaryOutputFile.is_open()) {
                                        std::cerr << "Error opening binary file for writing!" << std::endl;
                                        sftp_reply_status(message, SSH_FX_FAILURE, "FAIL" );
                                        break;
                                    }
                                    
                                    // [TODO] client needs a handle to keep track of networking, kinda like cookies
                                    // Also for security since we don't want to allow client to dictate by filepath
                                    // the file to get since this could lead to exfiltration if the path is not filtered
                                    //
                                    // [WHY] why use ssh_string?
                                    ssh_string foo9 = ssh_string_from_char("filehandleuuid");
                                    sftp_reply_handle(message,foo9 ); // handshake client ssh_string handle to open file

                                    //Read incoming client messages containing put
                                    sftp_client_message message_data;
                                    // Inner sftp loop to get binary data
                                    while ((message_data = sftp_get_client_message(sftp))!= nullptr) { 
                                        uint8_t sftp_message_type = sftp_client_message_get_type(message_data); 
                                        const char *  my_data = sftp_client_message_get_data(message_data); 
                                        ssh_string my_string = message_data->data;

                                        size_t my_sftp_length = ssh_string_len(my_string);
                                        //std::cout << "sizeof:  " << ssh_string_len(my_string) << std::endl;
                                        //std::cout << "id:  " << message->id << std::endl;
                                        uint64_t my_sftp_offset =  (uint64_t)message_data->offset;
                                        //std::cout << "offset:  " << my_sftp_offset << std::endl;

                                        switch (sftp_message_type) {
                                            case SSH_FXP_WRITE: { //write data to file
                                                //std::cout << "write" << std::endl;
                                                
                                                binaryOutputFile.seekp(my_sftp_offset, std::ios::beg);
                                                binaryOutputFile.write(my_data, my_sftp_length);
                                                sftp_reply_status(message_data, SSH_FX_OK, "OK"); //I processed this data please send more
                                                break;
                                            }
                                            case SSH_FXP_CLOSE: {
                                                //std::cout << "close" << std::endl;
                                                binaryOutputFile.seekp(my_sftp_offset, std::ios::beg);
                                                binaryOutputFile.write(my_data, my_sftp_length);
                                                binaryOutputFile.close();
                                                sftp_reply_status(message_data, SSH_FX_OK, "OK"); //received client closed
                                                sftp_server_free(sftp);
                                                return;
                                            }
                                            default: { // when will this get hit?
                                                std::cerr << "Unsupported SFTP operation (type " << static_cast<int>(sftp_message_type) << ")" << std::endl;
                                                sftp_reply_status(message, SSH_FX_OP_UNSUPPORTED, "Operation not supported");
                                                break;
                                            }
                                        }
                                    }
                                    break;
                                }

                                case SSH_FXP_REALPATH: { // [WHY] is this first request from client
                                    const char* path = sftp_client_message_get_filename(message);
                                    std::cout << "Received SSH_FXP_REALPATH request for: " << path << std::endl;
                                    char* resolved_path = realpath(path, nullptr);
                                    if (resolved_path!= nullptr) {
                                        sftp_attributes attr;
                                        memset(&attr, 0, sizeof(sftp_attributes_struct)); // Set all attributes to 0
                                        // Set relevant attributes if needed (e.g., permissions, size, etc.)
                                        sftp_reply_name(message, resolved_path, attr); // Pass the address of attr
                                        free(resolved_path); 
                                    } else {
                                        sftp_reply_status(message, SSH_FX_NO_SUCH_FILE, "Path not found");
                                    }
                                    break; // Add break statement
                                }

				                /*case SSH_FXP_MKDIR: { //this works but needs security wrapper to fence in client sent path
                                    std::cout << "2025 mkdir"  << std::endl;
                                    const char* oopath = sftp_client_message_get_filename(message); // Get path from the message
                                    std::cout << oopath  << std::endl;
                                    if (mkdir(oopath, 0777) != 0) {
                                        std::cerr << "Error creating directory " << oopath << ": " << strerror(errno) << std::endl;
                                    }
                                    sftp_reply_status(message, SSH_FX_OK, "goo goo"); //hyphothesis, need this back and forth
                                    break;
                                }*/
                                default: { // Only support a limited number of sftp commands for security
                                    std::cerr << "Unsupported SFTP operation (type " << static_cast<int>(sftp_message_type) << ")" << std::endl;
                                    sftp_reply_status(message, SSH_FX_OP_UNSUPPORTED, "Operation not supported");
                                    break;
                                }
                            }
                        }
                    }
                }
                ssh_message_free(message); // Free the message (if it wasn't already freed in the shell request case)
            }

            if (current_type == PTY) {
                const char* greeting = "Bella Server\r\n";
                char buffer[8]; // buffer to hold keystrokes
                std::string line_buffer; // Buffer to accumulate a line
                int nbytes;
                char esc_buffer[8]; // Buffer for escape sequences
                int esc_index = 0;   // Index for the escape sequence buffer
                // 2. Using regular expressions for more robust parsing (handles variations in whitespace, etc.)
                std::regex load_regex(R"(^\s*load\s+(https?://\S+\.bsz)\s*$)"); // URL must end in .bsz
                std::smatch match;

                while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
                    for (int i = 0; i < nbytes; ++i) { // Loop through the received bytes (nbytes might be > 1)
                        // Handle escape sequences (arrow keys, etc.)
                        if (buffer[i] == '\033') { // Escape character
                            esc_index = 0;      // Start a new escape sequence
                            esc_buffer[esc_index++] = buffer[i];
                            esc_buffer[esc_index++] = buffer[i+1];
                            esc_buffer[esc_index++] = buffer[i+2];
                            esc_buffer[esc_index] = '\0'; // Null-terminate , only captures max esc seq of 2 bytes
                        } else if (esc_index > 0) { // Building escape sequence
                            // Check for arrow keys (and other escape sequences)
                            if (strcmp(esc_buffer, "\033[A") == 0) { // Up arrow key
                                std::cout << "Up arrow" << std::endl;
                            } else if (strcmp(esc_buffer, "\033[B") == 0) { // Down arrow key
                                std::cout << "Down arrow" << std::endl;
                            } else if (strcmp(esc_buffer, "\033[C") == 0) { // Right arrow key
                                std::cout << "Right arrow" << std::endl;
                            } else if (strcmp(esc_buffer, "\033[D") == 0) { // Left arrow key
                                std::cout << "Left arrow" << std::endl;
                            }
                            esc_index = 0; // Reset for next sequence
                            break;
                        } else { 
                            // Process regular characters
                            switch (buffer[i]) {
                                case 127: // Delete/Backspace character
                                    if (!line_buffer.empty()) // Ensure there's something to delete
                                        line_buffer.pop_back();
                                    ssh_channel_write(channel, "\b \b", 3); // Send backspace, space, backspace to erase on client
                                    break;
                                case '\r': // Carriage return
                                case '\n': // Remove any carriage return or newline characters from the line buffer
                                    line_buffer.erase(std::find(line_buffer.begin(), line_buffer.end(), '\r'), line_buffer.end());
                                    line_buffer.erase(std::find(line_buffer.begin(), line_buffer.end(), '\n'), line_buffer.end());

                                    // Send carriage return and newline to the client to move the cursor to the next line
                                    ssh_channel_write(channel, "\r\n", 2);

                                    // Check if the user entered the "exit" command
                                    if (line_buffer == "exit") {
                                        const char* goodbye = "Goodbye!\n";
                                        ssh_channel_write(channel, goodbye, strlen(goodbye)); // Send goodbye message
                                        ssh_channel_close(channel);  // Close the channel
                                        ssh_channel_free(channel);   // Free channel resources
                                        //goto cleanup;  // Jump to the cleanup section
                                        return;
                                    }
                                    /*if (std::regex_search(line_buffer, match, load_regex)) {
                                        std::string url = match[1]; // The captured URL (group 1)

                                        try {
                                            std::filesystem::path url_path(url); // Construct a path object from the URL
                                            std::string filename = url_path.filename().string(); // Extract filename

                                            std::cout << "URL: " << url << std::endl;
                                            std::cout << "Filename: " << filename << std::endl;

                                            // --- 1. Download a file using libcurl ---
                                            CURL *curl;

                                            if (std::filesystem::exists(filename)) {
                                                std::cout << "File exists!" << std::endl;
                                            } else {

                                                std::filesystem::path filepath(filename); // filename is your std::string
                                                std::ofstream outfile(filepath, std::ios::binary); // Open in binary mode (important!)
                                                if (outfile.is_open()) {
                                                    CURL* curl;
                                                    CURLcode res;

                                                    curl = curl_easy_init();
                                                    if (curl) {
                                                        curl_easy_setopt(curl, CURLOPT_URL, url);  // url is the URL string
                                                        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
                                                        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &outfile); // Pass the std::ostream*

                                                        res = curl_easy_perform(curl);

                                                        if (res != CURLE_OK) {
                                                            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
                                                        }

                                                        curl_easy_cleanup(curl);
                                                        outfile.close(); // Close the file (important!)
                                                    } else {
                                                      std::cerr << "curl_easy_init() failed" << std::endl;
                                                    }
                                                } else {
                                                    std::cerr << "Error opening file: " << strerror(errno) << std::endl;
                                                    // Handle the error
                                                }
                                            }
                                        } catch (const std::exception& e) {
                                            std::cerr << "Error processing URL: " << e.what() << std::endl;
                                        }

                                    }*/

                                    std::cout << line_buffer << " " << nbytes << std::endl; // Print the received line (for debugging)
                                    line_buffer.clear(); // Clear the line buffer for the next line
                                    break;

                                default: // Any other character
                                    line_buffer += buffer[i];
                                    // Echo the received character back to the client
                                    ssh_channel_write(channel, &buffer[i], 1);
                                    break;
                            } // End of switch
                        } // End of else (regular character handling)
                    } 
                }
            } else if (current_type == SFTP) {
                std::cout << "sftp " <<  std::endl;

            }
            //cleanup:
            //    ssh_channel_close(channel);
            //    ssh_channel_free(channel);
         }
        ssh_message_free(message);
    }
}

int main() {
    ssh_bind sshbind;
    ssh_session session;
    int rc;

    // Initialize ssh_bind
    sshbind = ssh_bind_new(); // Creates a new SSH server bind
    if (!sshbind) {
        std::cerr << "Failed to create ssh_bind" << std::endl;
        return -1;
    }

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, BINDADDR);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, BINDPORT);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, HOSTKEY);

    // ssh-keygen -t rsa server_key
    // [TODO] create the server key if it doesn't exist
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "./server_key");

    if (ssh_bind_listen(sshbind) < 0) {
        std::cerr << "Error listening: " << ssh_get_error(sshbind) << std::endl;
        ssh_bind_free(sshbind);
        return -1;
    }

    std::cout << "SSH server listening on port " << BINDPORT << std::endl;
    while (true) {
        session = ssh_new();
        if (ssh_bind_accept(sshbind, session) < 0) {
            std::cerr << "Error accepting connection: " << ssh_get_error(sshbind) << std::endl;
            break;
        }

        if (ssh_handle_key_exchange(session) != SSH_OK) {
            std::cerr << "Error during key exchange: " << ssh_get_error(session) << std::endl;
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        // Authentication
        bool authenticated = false;
        while (!authenticated) {
            ssh_message message = ssh_message_get(session);
            if (!message) break;
            if (ssh_message_type(message) == SSH_REQUEST_AUTH &&
                ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
                const char* user = ssh_message_auth_user(message);
                const char* pass = ssh_message_auth_password(message);

                if (strcmp(user, USERNAME) == 0 && strcmp(pass, PASSWORD) == 0) {
                    ssh_message_auth_reply_success(message, 0);
                    authenticated = true;
                } else {
                    ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD); //Needed
                    ssh_message_reply_default(message);
                }
            } else {
                ssh_message_reply_default(message);
            }
            ssh_message_free(message);
        }

        if (authenticated) {
            std::cout << "Client authenticated!" << std::endl;
            handle_client(session); // [TODO] run async
        } else {
            std::cout << "Authentication failed!" << std::endl;
            ssh_disconnect(session);
        }
        ssh_free(session);
    }
    ssh_bind_free(sshbind);
    return 0;
}
