// Naive learning-to-code sftp server with bella render integration
// this sftp implementation only allows uploading of .bsz file and downloading of image files
// it does not support other sftp operations
// it also limits the scope of file operations to the working dir of the server for security
// also filename requests are ignored with the server using bellasdftp.bsz as the only file


#define WITH_SERVER

#include "bella_sdk/bella_engine.h"
#include <thread>

using namespace dl;
using namespace dl::bella_sdk;

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

// This is the global dl log callback, where all messages will be received, and you can print
// them as you see fit.
//
static int s_logCtx = 0;
static void log(void* /*ctx*/, LogType type, const char* msg)
{
    switch (type)
    {
    case LogType_Info:
        DL_PRINT("[INFO] %s\n", msg);
        break;
    case LogType_Warning:
        DL_PRINT("[WARN] %s\n", msg);
        break;
    case LogType_Error:
        DL_PRINT("[ERROR] %s\n", msg);
        break;
    case LogType_Custom:
        DL_PRINT("%s\n", msg);
        break;
    }
}

enum sshSessionType {
  PTY,
  SFTP
};

std::map<uint8_t, std::string> sftp_op_names = {
    {SSH_FXP_INIT, "SSH_FXP_INIT"},
    {SSH_FXP_VERSION, "SSH_FXP_VERSION"},
    {SSH_FXP_OPEN, "SSH_FXP_OPEN"},
    {SSH_FXP_CLOSE, "SSH_FXP_CLOSE"},
    {SSH_FXP_READ, "SSH_FXP_READ"},
    {SSH_FXP_WRITE, "SSH_FXP_WRITE"},
    {SSH_FXP_LSTAT, "SSH_FXP_LSTAT"},
    {SSH_FXP_FSTAT, "SSH_FXP_FSTAT"},
    {SSH_FXP_SETSTAT, "SSH_FXP_SETSTAT"},
    {SSH_FXP_FSETSTAT, "SSH_FXP_FSETSTAT"},
    {SSH_FXP_OPENDIR, "SSH_FXP_OPENDIR"},
    {SSH_FXP_READDIR, "SSH_FXP_READDIR"},
    {SSH_FXP_REMOVE, "SSH_FXP_REMOVE"},
    {SSH_FXP_RENAME, "SSH_FXP_RENAME"},
    {SSH_FXP_RMDIR, "SSH_FXP_RMDIR"},
    {SSH_FXP_MKDIR, "SSH_FXP_MKDIR"},
    {SSH_FXP_SYMLINK, "SSH_FXP_SYMLINK"},
    {SSH_FXP_REALPATH, "SSH_FXP_REALPATH"},
    {SSH_FXP_STAT, "SSH_FXP_STAT"},
    {SSH_FXP_EXTENDED, "SSH_FXP_EXTENDED"}
};


// EngineObserver subscribes to an Engine instance and receives various messages with status,
// images as they become available, and so forth. You only need to implement the overrides you
// wish, most of which come with a "pass" argument, indicating the render pass to which they
// pertain.
//
// Note that these are called from a non-GUI thread, so if you are running in a GUI you will
// need to marshal these calls to the GUI thread.
//
struct MyEngineObserver : public EngineObserver
{
    void onStarted(String pass) override
    {
        logInfo("Started pass %s", pass.buf());
    }
    void onStatus(String pass, String status) override
    {
        logInfo("%s [%s]", status.buf(), pass.buf());
    }


    void onProgress(String pass, Progress progress) override
    {
        std::ofstream logfile;
        if (!logfile.is_open()) {
            logfile.open("logfile.txt", std::ios::trunc); // Open in truncate mode to overwrite
            if (!logfile.is_open()) {
                std::cerr << "Error opening log file!" << std::endl;
                return; // Or handle the error as appropriate
            }
        }
        // Use vfprintf for formatted output like printf:
        // This example uses a fixed size buffer, for more robust string formatting, consider using snprintf
        char buffer[1024]; // Adjust size as needed
        snprintf(buffer, sizeof(buffer), "%s [%s]", progress.toString().buf(), pass.buf()); // Safer than sprintf
        logfile <<  buffer << std::endl;  // Write to the file
        logInfo("%s [%s]", progress.toString().buf(), pass.buf());
        logfile.close();

    }
    void onImage(String pass, Image image) override
    {
        logInfo("We got an image %d x %d.", (int)image.width(), (int)image.height());
    }
    void onError(String pass, String msg) override
    {
        logError("%s [%s]", msg.buf(), pass.buf());
    }
    void onStopped(String pass) override
    {
        logInfo("Stopped %s", pass.buf());
    }
};

// Write function used by curl (modified to use std::ostream)
size_t write_data(void* buffer, size_t size, size_t nmemb, std::ostream* stream) {
    size_t written = size * nmemb;
    if (stream->write(static_cast<char*>(buffer), written)) {
        return written; // Return the number of bytes written
    }
    return 0; // Indicate an error
}

void handle_client(ssh_session client_session, Engine engine) {
    ssh_message message; // bridge class to go from developer friendly to efficient wire format
    while ((message = ssh_message_get(client_session))) { // client handler session loop post authentication
        
        /*Channel Handling: SSH servers need to be able to handle different types of channel requests. 
        This if statement allows the server to specifically identify and handle requests for session channels.
        Session channels are the most common type of channel. 
        They are used for interactive shell sessions, executing commands, and establishing other subsystems like SFTP.
        */

        sshSessionType current_ssh_type = PTY;
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
            ssh_channel channel = ssh_message_channel_request_open_reply_accept(message); // Accept a channel
            ssh_message_free(message); // Free any memory used by ssh_message

            while ((message = ssh_message_get(client_session))!= nullptr) { // ssh messaging outer loop 
                if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) { // is channel request?
                    if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY) { // is pseudo-terminal (PTY)?
                        std::cout << "pty" << std::endl;
                        ssh_message_channel_request_reply_success(message); // Approve
                        ssh_message_free(message);  // Free the message (it's no longer needed)
                        break; // Exit loop to start interacting with the client
                    } else if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SUBSYSTEM) { // Check for SFTP request
                        ssh_message_channel_request_reply_success(message); // Approve
                        ssh_message_free(message);  // Free the message (it's no longer needed)
                        // Now you have the channel, you can create the sftp session
                        sftp_session sftp = sftp_server_new(client_session, channel); // create sftp session
                        if (sftp == NULL) {
                            fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(client_session)); 
                            return; 
                        }
                        sftp_client_message message; // new messaging pathway
                        int rc = sftp_server_init(sftp); // initialize sftp session
                        if (rc != 0) {
                            std::cout << "failed to initialize sftp session" << std::endl;
                            std::cout << sftp_get_error(sftp) << std::endl;
                            break;
                        }
                        uint32_t flags_for_write = SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC;
                        uint32_t flags_for_read = SSH_FXF_READ;

                        uint8_t sftp_message_type;
                        uint32_t message_flags;
                        uint32_t request_id;
                        char* sftp_filename;
                        std::string write_file = "./oomer.bsz";            
                        std::string read_file = "./oomer.png";            
                        const size_t chunk_size = 32768;
                        std::vector<char> sftp_buffer(chunk_size); // Buffer to hold each chunk
                        std::ofstream binaryOutputFile;// for writing
                        std::ifstream binaryInputFile;// for reading
                        ssh_string my_handle = NULL;
                        std::streamsize bytes_read_in_chunk;

                        // sftp message outer loop,stay in this loop until client disconnects
                        while ((message = sftp_get_client_message(sftp))!= nullptr) { 
                            sftp_message_type = sftp_client_message_get_type(message); //type is opcode
                            request_id = message->id;
                            std::cout << "request_id: " << request_id << std::endl;
                            switch (sftp_message_type) {
                                case SSH_FXP_LSTAT: { 
                                    const char* sftp_filename_cstr = sftp_client_message_get_filename(message); //type is opcode
                                    if ( sftp_filename_cstr == nullptr ) {
                                        std::cerr << "sftp_filename_cstr is nullptr" << std::endl;
                                        sftp_reply_status(message, SSH_FX_FAILURE, "FAIL" );
                                    } else {
                                        std::string sftp_filename(sftp_filename_cstr);
                                        std::cout << "sftp_filename: " << sftp_filename << std::endl;
                                    }
                                    std::cerr << "SSH_FXP_LSTAT" <<  std::endl;
                                    sftp_attributes my_foo_attrib = (sftp_attributes)malloc(sizeof(struct sftp_attributes_struct)); // Allocate memory using malloc
                                    if (my_foo_attrib == NULL) { // Check for allocation failure!
                                        return; // Exit function on allocation error
                                    }
                                    memset(my_foo_attrib, 0, sizeof(struct sftp_attributes_struct)); // Initialize to 0
                                    my_foo_attrib->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME | SSH_FILEXFER_ATTR_UIDGID;
                                    my_foo_attrib->size = 42345418;
                                    my_foo_attrib->uid = 1000;
                                    my_foo_attrib->gid = 1000;
                                    my_foo_attrib->permissions = 0644;
                                    my_foo_attrib->atime = 1713238400;
                                    my_foo_attrib->mtime = 1713238400;

                                    if (sftp_filename == "./progress") {
                                        std::ifstream log_file("logfile.txt");
                                        if (log_file.is_open()) {
                                            std::string log_line;
                                            if (std::getline(log_file, log_line)) { // Reads the entire line, including spaces
                                                sftp_reply_name(message, log_line.c_str(), my_foo_attrib); // Pass the address of attr
                                            } else {
                                                sftp_reply_name(message, NULL, my_foo_attrib); // Pass the address of attr
                                            }
                                            log_file.close();
                                        }
                                    } else {
                                        sftp_reply_attr(message, my_foo_attrib );
                                    }
                                    free(my_foo_attrib);

                                    break;
                                }

                                case SSH_FXP_READ: { 
                                    std::cerr << "SSH_FXP_READ" <<  std::endl;
                                    binaryInputFile.read(sftp_buffer.data(), chunk_size); // read the file into the buffer
                                    bytes_read_in_chunk = binaryInputFile.gcount(); // Actual bytes read
                                    if (bytes_read_in_chunk > 0) {
                                        std::cout << "Read chunk of " << bytes_read_in_chunk << " bytes." << std::endl;
                                        int rc = sftp_reply_data(message, sftp_buffer.data() , bytes_read_in_chunk); // send the data to the client
                                        if (rc != 0) {
                                            std::cerr << "Error during file read." << std::endl;
                                            return; // Error occurred, exit loop
                                        }
                                    } else if (bytes_read_in_chunk == 0) { // No bytes read in this chunk. Check why:
                                            std::cout << "Reached end of file." << std::endl;
                                            //sftp_reply_data(message, nullptr , 0); // send the data to the client
                                            sftp_reply_status(message, SSH_FX_EOF, "EOF"); // send the data to the client
                                            break; // End of file reached, exit handle_client
                                    } else if (binaryInputFile.fail() || binaryInputFile.bad()) {
                                        std::cerr << "Error during file read." << std::endl;
                                        return; // Error occurred, exit loop
                                    } else {
                                        std::cerr << "Error during file read." << std::endl;
                                        break; // Error occurred, exit loop
                                    }
                                    break;
                                } 
                                case SSH_FXP_MKDIR: {
                                    std::cerr << "SSH_FXP_MKDIR" <<  std::endl;
                                    engine.scene().read("./oomer.bsz");
                                    engine.scene().camera()["resolution"] = Vec2 {200, 200};
                                    engine.start();
                                    sftp_reply_status(message, SSH_FX_OK , ""); // send the data to the client
                                    break;
                                }

                                case SSH_FXP_STAT: { // only used for read
                                    /*const char* sftp_filename_cstr = sftp_client_message_get_filename(message); //type is opcode
                                    if ( sftp_filename_cstr == nullptr ) {
                                        std::cerr << "sftp_filename_cstr is nullptr" << std::endl;
                                        sftp_reply_status(message, SSH_FX_FAILURE, "FAIL" );
                                        break;
                                    } else {
                                        std::string sftp_filename(sftp_filename_cstr);
                                        std::cout << "sftp_filename: " << sftp_filename << std::endl;
                                    }*/
                                    struct stat file_stat;
                                    if ( lstat( read_file.c_str(), &file_stat ) == 0 ) {
                                        sftp_attributes bella_attrib = (sftp_attributes)malloc(sizeof(struct sftp_attributes_struct)); // Allocate memory using malloc
                                        if ( bella_attrib == NULL ) { // Check for allocation failure!
                                            std::cerr << "Memory allocation failed for sftp_attributes." << std::endl;
                                            return; // Exit function on allocation error
                                        }
                                        memset(bella_attrib, 0, sizeof(struct sftp_attributes_struct)); // Initialize to 0
                                        bella_attrib->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME | SSH_FILEXFER_ATTR_UIDGID;
                                        bella_attrib->size = file_stat.st_size;
                                        bella_attrib->uid = file_stat.st_uid;
                                        bella_attrib->gid = file_stat.st_gid;
                                        bella_attrib->permissions = file_stat.st_mode;
                                        bella_attrib->atime = file_stat.st_atime;
                                        bella_attrib->mtime = file_stat.st_mtime;
                                        sftp_reply_attr(message, bella_attrib ); //I processed this data please send more
                                        free(bella_attrib); 
                                    } else { 
                                        int status_code;
                                        if (errno == ENOENT) {
                                            status_code = SSH_FX_NO_SUCH_FILE;
                                            std::cerr << "  File not found: "  << std::endl;
                                        } else if (errno == EACCES) {
                                            status_code = SSH_FX_PERMISSION_DENIED;
                                            std::cerr << "  Permission denied to access: " << std::endl;
                                        } else {
                                            status_code = SSH_FX_FAILURE; // Generic failure
                                            std::cerr << "  Error getting file status for: " << " (errno: " << errno << ")" << std::endl;
                                        }
                                        sftp_reply_status(message, SSH_FX_FAILURE, "FAIL" );
                                    }
                                    break;
                                }

                                case SSH_FXP_WRITE: { //write data to file
                                    const char *  my_data = sftp_client_message_get_data(message); 
                                    ssh_string my_string = message->data;
                                    size_t my_sftp_length = ssh_string_len(my_string);
                                    uint64_t my_sftp_offset =  (uint64_t)message->offset;
                                    binaryOutputFile.seekp(my_sftp_offset, std::ios::beg);
                                    binaryOutputFile.write(my_data, my_sftp_length);
                                    sftp_reply_status(message, SSH_FX_OK, "");
                                    break;
                                }

                                case SSH_FXP_CLOSE: {
                                    std::cout << "SSH_FXP_CLOSE" << std::endl;
                                    if ((message_flags & flags_for_write ) == flags_for_write) { // handle put
                                        binaryOutputFile.close();
                                    } else if ( (message_flags & flags_for_read ) == flags_for_read) { // handle get
                                        binaryInputFile.close();
                                    }
                                    sftp_reply_status(message, SSH_FX_EOF, ""); //received client closed
                                    break;
                                }

                                case SSH_FXP_OPEN: { // handles both read and write
                                    std::cout << "SSH_FXP_OPEN" << std::endl;
                                    message_flags = sftp_client_message_get_flags(message);
                                    if ((message_flags & flags_for_write ) == flags_for_write) { // handle put
                                        std::cout << "  SSH_FXF_WRITE flag is SET (Client intends to upload)." << std::endl;
                                        binaryOutputFile.open(write_file, std::ios::binary);
                                        if (!binaryOutputFile.is_open()) {
                                                std::cerr << "Error opening binary file for writing!" << std::endl;
                                                sftp_reply_status(message, SSH_FX_FAILURE, "FAIL" );
                                                break;
                                        }
                                    } else if  ( ( message_flags & SSH_FXF_READ ) != 0 ) { // handle get
                                        std::cout << "  SSH_FXF_READ flag is SET (Client intends to read/download)." << std::endl;
                                        binaryInputFile.open(read_file, std::ios::binary);// for reading
                                        if (!binaryInputFile.is_open()) {
                                            std::cerr << "Error opening binary file for reading!" << std::endl;
                                            sftp_reply_status(message, SSH_FX_FAILURE, "FAIL" );
                                            break;
                                        }
                                    }
                                    my_handle = ssh_string_from_char("foo foo"); //[TODO] currently not a uuid because only one sftp client is allowed
                                    // Since multiple clients would require a uuid, this is a placeholder for now
                                    sftp_reply_handle( message, my_handle ); // handshake client ssh_string handle to open file
                                    std::cout << "END SSH_FXP_OPEN" << std::endl;
                                    break;
                                }

                                case SSH_FXP_REALPATH: { // get real path of file
                                    // Standard sftp operation can handle symbolic links etc and an absolute path is required
                                    // This program limits path operations to the working directory
                                    // This is a security measure to prevent the server from being used to read arbitrary files
                                    const char* client_filename = sftp_client_message_get_filename(message);
                                    std::cout << "Received SSH_FXP_REALPATH request for: " << client_filename << std::endl;
                                    //char* resolved_path = realpath(client_filename, nullptr);
                                    const char* resolved_path = ".";
                                    std::cout << "Resolved path: " << resolved_path << std::endl;

                                    struct stat file_stat;
                                    if (stat(resolved_path, &file_stat) == 0) { // Call stat
                                        // stat successful!
                                        std::cout << "REALPATH stat successful!" << std::endl;
                                        sftp_attributes my_sftp_attrib = (sftp_attributes)malloc(sizeof(struct sftp_attributes_struct));
                                        if(my_sftp_attrib == NULL) {
                                            std::cerr << "Memory allocation failed for sftp_attributes." << std::endl;
                                            return;
                                        }
                                        memset(my_sftp_attrib, 0, sizeof(struct sftp_attributes_struct)); // Initialize to 0    
                                        my_sftp_attrib->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME | SSH_FILEXFER_ATTR_UIDGID;
                                        my_sftp_attrib->size = 0; // Size is not relevant for a directory
                                        my_sftp_attrib->uid = file_stat.st_uid;
                                        my_sftp_attrib->gid = file_stat.st_gid;
                                        my_sftp_attrib->permissions = file_stat.st_mode;
                                        my_sftp_attrib->atime = file_stat.st_atime;
                                        my_sftp_attrib->mtime = file_stat.st_mtime;
                                        if (client_filename!= nullptr) {
                                            std::string sftp_filename(client_filename);
                                            if (sftp_filename == "./progress") {
                                                std::cout << "REALPATH progress" << std::endl;

                                                std::ifstream log_file("logfile.txt");
                                                if (log_file.is_open()) {
                                                    std::string log_line;
                                                    if (std::getline(log_file, log_line)) { // Reads the entire line, including spaces
                                                        sftp_reply_name(message, log_line.c_str(), my_sftp_attrib); // Pass the address of attr
                                                    } else {
                                                        sftp_reply_name(message, "Arbitarty text", my_sftp_attrib); // Pass the address of attr
                                                    }
                                                    log_file.close();
                                                    break;
                                                }
                                            }
                                        }
                                        sftp_reply_name(message, resolved_path, my_sftp_attrib); // Pass the address of attr
                                        std::cout << "REALPATH sftp_reply_name" << std::endl;
                                        free(my_sftp_attrib); // Free the allocated memory
                                    }
                                    break;
                                }

				                case SSH_FXP_REMOVE: { 
                                    std::cout << "Overriding mkdir as engine.start()" << std::endl;
                                    //engine.start();
                                    sftp_reply_status(message, SSH_FX_OK, ""); //hyphothesis, need this back and forth
                                    break;
                                }
                                default: { // Only support a limited number of sftp commands for security
                                    if (sftp_op_names.count(sftp_message_type)) {
                                        std::cerr << "Unsupported SFTP operation: " << sftp_op_names[sftp_message_type] << std::endl;
                                    } else {
                                        std::cerr << "type: Unknown (" << static_cast<int>(sftp_message_type) << ")" << std::endl; // Handle unknown types
                                    }
                                    sftp_reply_status(message, SSH_FX_OP_UNSUPPORTED, "Operation not supported");
                                    break;
                                }
                            }
                        }
                    }
                }
                ssh_message_free(message); // Free the message (if it wasn't already freed in the shell request case)
            }
            if (current_ssh_type == PTY) {
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
            } else if (current_ssh_type == SFTP) {
                std::cout << "sftp " <<  std::endl;
            }
         }
        ssh_message_free(message);
    }
}


// We will use the dl_core main helper here. This gives us a helpful Args instance to use, and
// also hides the confusing details of dealing with main vs. WinMain on windows, and gives us
// utf8-encoded args when the application is unicode.
//
#include "dl_core/dl_main.inl"
int DL_main(Args& args)
{


//int main() {
    // Very early on, we will subscribe to the global bella logging callback, and ask to flush
    // any messages that may have accumulated prior to this point.
    //
    subscribeLog(&s_logCtx, log);
    flushStartupMessages();

    logBanner("Bella Engine SDK (version: %s, build date: %llu)",
        bellaSdkVersion().toString().buf(),
        bellaSdkBuildDate()
    );

    // Create an engine to use for our command line function, and for rendering. We will load our
    // definitions, though it is also possible to define nodes at runtime. When we call loadDefs
    // this way, with no argument, the scene loads bella's internal built-in node definitions.
    //
    Engine engine;
    engine.scene().loadDefs();

    //auto path = args.iPath().canonical();
    //auto path = "./oomer.bsz";
    //if (path.isEmpty())
    //{
    //    logInfo("No input file given, using standard Bella preview scene.");
    //auto path = bella_sdk::previewPath();
    //engine.scene().read(path);
    //}

    // We have a file, so we'll now give it to the engine's scene to read.
    //
    //if (!engine.scene().read(path))
    //{
    //    logError("Failed to read %s from %s", path.buf(), fs::currentDir().buf());
    //    return 1;
    //}

    // Starting rendering is as simple as calling start(). We'll subscribe an observer to the scene
    // here to receive messages from the engine as it starts up and begins to render.
    //
    MyEngineObserver engineObserver;
    engine.subscribe(&engineObserver);

    //logInfo("Rendering %s", dl::Path::canonical(path).buf());
    ssh_bind sshbind;
    ssh_session session;
    int rc;

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
            handle_client(session, engine); // [TODO] run async
        } else {
            std::cout << "Authentication failed!" << std::endl;
            ssh_disconnect(session);
        }
        ssh_free(session);
    }
    ssh_bind_free(sshbind);
    return 0;
    //}

    //engine.stop();
    //engine.unsubscribe(&engineObserver);

    //logInfo("Done.");
    //return 0;
}

