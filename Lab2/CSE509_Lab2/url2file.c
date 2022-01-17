#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h> 
#include <sys/syscall.h>   /* For SYS_write etc */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define debug 0

const int long_size = sizeof(long);

int get_data(char * str, int child, long addr) {
	
	int len = 0;
	int i = 0, j = 0;
	int flag = 1;
	
	union u {
		long val;
		char chars[long_size];
	}data;
	
	char *curr_ptr ; 
	curr_ptr = str ; 

	while(flag) {
		data.val = ptrace(PTRACE_PEEKDATA, child, addr + i*8, NULL);
		for (j = 0; j < long_size; j++) {
			if (data.chars[j] == '\0') {
				flag = 0;
				break;
			}
		}
		memcpy(curr_ptr, data.chars, j);
		curr_ptr = curr_ptr +j;
		len = len+j;
		if (flag == 0) {
			(*curr_ptr) = '\0';
			break;
		}
		i++;
	}
	return len;
}



// put argument into the register
void copy_file_path_to_rdi(int child, long addr) {
	
	union u {
		long val;
		char chars[long_size];
	}data;
	
	char * file_path = "/tmp/url2file/file.tmp";
	int len = strlen(file_path);
	int i,j;
	i = 0;
	j = len/long_size;
	

	char * laddr;
	laddr = file_path;
	
	while( i < j ) {
		memcpy(data.chars, laddr, long_size);
		ptrace(PTRACE_POKEDATA, child, addr + i*8, data.val);
		++i;
		laddr += long_size;
	}
	
	j = len % long_size;
	if (j != 0) {
		data.val = 0;
		memcpy(data.chars, laddr, j);
		ptrace(PTRACE_POKEDATA, child, addr + i*8, data.val);
	}
}


int main(int argc, char **argv[]) {

	pid_t child;
	long rax, orig_rax;
	long params[3];
	int status, syscall_execve, syscall_stat, syscall_openat, syscall_symlink;
	syscall_execve = 0;
	syscall_stat = 0;
	syscall_openat = 0;
	syscall_symlink =0;
	struct user_regs_struct regs;

	status = 0;

	int file_created = 0;
	system("rm -rf /tmp/url2file; mkdir /tmp/url2file");

	// revisit this
	char *url = calloc(4097, sizeof(char));
	
	char *args[0];
	args[0] = argv[1];
	args[1] = argv[2];
	args[2] = NULL;
	
	child = fork();
	if (child == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execvp(argv[1], &argv[1]);
	}
	else {
		while(1) {
			wait(&status);
			if(WIFEXITED(status))
				break;
			ptrace(PTRACE_GETREGS, child, 0, &regs);
			orig_rax = regs.orig_rax;
			
			
			if (orig_rax == SYS_openat || orig_rax == SYS_linkat) {
				if(syscall_openat == 0) {
					// openat is mostly used by most programs to open a file
					syscall_openat = 1;
					params[0] = regs.rdi;
					params[1] = regs.rsi;
					params[2] = regs.rdx;
	
					#ifdef DEBUG
					printf("syscall_openat() called with %ld, %ld, %ld\n", 
								params[0], params[1], params[2]);
					#endif
					// openat(int dirfd, const char *pathname, int flags)
					int param_len = get_data(url, child, params[1]);
					if (strncmp(url, "http://",7) == 0 || strncmp(url, "https://",8) == 0 || strncmp(url, "www",3) == 0) {
						#ifdef DEBUG
						printf("########syscall_stat##########\n");
						#endif
						if(file_created == 0){
							char *wget_str = "wget -q -O /tmp/url2file/file.tmp";
							char *system_arg = malloc(50 + param_len);
							int i = 0;
							for ( i = 0; i < strlen(wget_str); i++) 
								system_arg[i] = wget_str[i];
							system_arg[i ++]  = ' '; 
							for (int j = 0; j < param_len; j++) {
								system_arg[i] = url[j];
								i++;
							}
							system_arg[i] = '\0';
							system(system_arg);
							file_created = 1;
							system("chmod 777 /tmp/url2file/file.tmp");
							free(system_arg);
						}
						copy_file_path_to_rdi(child, params[1]);	
					}
				}
				else { 
					rax = ptrace(PTRACE_PEEKUSER, child, 8 * RAX, NULL);
					#ifdef DEBUG
					printf("stat() returned with %ld\n", rax);
					#endif
					syscall_openat = 0;
				}
			 } 
			 if (orig_rax == SYS_stat || orig_rax == SYS_statfs) {
				if(syscall_stat == 0) {
					syscall_stat = 1;
					params[0] = regs.rdi;
					params[1] = regs.rsi;
					params[2] = regs.rdx;

					#ifdef DEBUG
					printf("syscall_stat() called with %ld, %ld, %ld\n", 
								params[0], params[1], params[2]);
					#endif
					int param_len = get_data(url, child, params[0]);

					if (strncmp(url, "http://",7) == 0 || strncmp(url, "https://",8) == 0 || strncmp(url, "www",3) == 0) {
						#ifdef DEBUG
						printf("########syscall_stat##########\n");
						printf("%s %d\n", url, len);
						#endif
						if(file_created == 0){
							char *wget_str = "wget -q -O /tmp/url2file/file.tmp";
							char *system_arg = malloc(50 + param_len);
							int i = 0;
							for ( i = 0; i < strlen(wget_str); i++) 
								system_arg[i] = wget_str[i];
							system_arg[i ++]  = ' '; 
							for (int j = 0; j < param_len; j++) {
								system_arg[i] = url[j];
								i++;
							}
							system_arg[i] = '\0';
							system(system_arg);
							file_created = 1;
							system("chmod 777 /tmp/url2file/file.tmp");
							free(system_arg);
						}
						copy_file_path_to_rdi(child, params[0]);
					}
				}
				else { 
					// system call exit 
					rax = ptrace(PTRACE_PEEKUSER, child, 8 * RAX, NULL);
					#ifdef DEBUG
					printf("stat() returned with %ld\n", rax);
					#endif
					syscall_stat = 0;
				}
			 } 

			  
			if (orig_rax == SYS_execve){
			 	if(syscall_execve == 0) {
			 		syscall_execve = 1;
			 	} else {
			 	if(syscall_execve == 1) {
			 		params[0] = regs.rdi;
				params[1] = regs.rsi;
				params[2] = regs.rdx;
				syscall_execve = 2;
								
				int param_len = get_data(url, child, params[0]);
				
				if (strncmp(url, "http://",7) == 0 || strncmp(url, "https://",8) == 0 || strncmp(url, "www",3) == 0) {
						#ifdef DEBUG
						printf("########syscall_stat##########\n");
						printf("%s %d\n", url, len);
						#endif
						if(file_created == 0){
							char *wget_str = "wget -q -O /tmp/url2file/file.tmp";
							char *system_arg = malloc(50 + param_len);
							int i = 0;
							for ( i = 0; i < strlen(wget_str); i++) 
								system_arg[i] = wget_str[i];
							system_arg[i ++]  = ' '; 
							for (int j = 0; j < param_len; j++) {
								system_arg[i] = url[j];
								i++;
							}
							system_arg[i] = '\0';
							system(system_arg);
							file_created = 1;
							system("chmod 777 /tmp/url2file/file.tmp");
							free(system_arg);
						}
						copy_file_path_to_rdi(child, params[0]);
					}
				
			 	
			 	}
				
			 	
			 	}
			 		
			 } 
			 
			 


			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		}
	}

	if(file_created == 1) {
		system("chmod 666 /tmp/url2file/file.tmp");
		system("rm /tmp/url2file/file.tmp");
	}
	system("rm -rf /tmp/url2file");
	
	return 0;
}

