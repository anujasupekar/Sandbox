#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>

struct sandbox {
  pid_t child;
  const char *progname;
};

struct sandb_syscall {
  int syscall;
  void (*callback)(struct sandbox*, struct user_regs_struct *regs);
};

struct sandb_syscall sandb_syscalls[] = {
  {__NR_read,            NULL},
  {__NR_write,           NULL},
  {__NR_exit,            NULL},
  {__NR_brk,             NULL},
  {__NR_mmap,            NULL},
  {__NR_access,          NULL},
  {__NR_open,            NULL},
  {__NR_fstat,           NULL},
  {__NR_close,           NULL},
  {__NR_mprotect,        NULL},
  {__NR_munmap,          NULL},
  {__NR_arch_prctl,      NULL},
  {__NR_exit_group,      NULL},
  {__NR_getdents,        NULL},
  {__NR_execve,		 NULL},
  {__NR_openat,		 NULL},
  {__NR_stat,		 NULL},
  {__NR_lstat,		 NULL},
  {__NR_statfs,		 NULL},
};

char * config;

void sandb_kill(struct sandbox *sandb) {
  kill(sandb->child, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}

void sandb_handle_syscall(struct sandbox *sandb) {
  int i;
  struct user_regs_struct regs;
  int read=0;
  char *val = malloc(4096);
  int allocated = 4096;
  unsigned long tmp;
  long orig_rax, rax;
  long buffer;
  int read_bit = 0;
  int read_permission = 1;
  int write_permission = 0;
  int readwrite_permission = 0;
  int exec_permission = 0;
  char *config_permission;

  if(ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs) < 0)
    err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

  for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) {
    if(regs.orig_rax == sandb_syscalls[i].syscall)

	 { if (regs.orig_rax == SYS_open)

		{
		 char *config_permission = handle_call(sandb);
		 printf("yess%s\n", config_permission);
		 buffer  = regs.rsi;
		 printf ("%ld buffer value\n", buffer);
		 if(buffer & O_WRONLY)
                 {
		  write_permission = 1;
		  read_permission = 0;
		  printf("yo");
		 }

		 if(buffer & O_RDWR)
	         readwrite_permission = 1;

		 if((read_permission == 1) && (config_permission[0] == 0))

                { printf("Process terminated");

                	sandb_kill(sandb);}


  		 if((write_permission == 1) && (config_permission[1] == 0))

      		 { printf("Process terminated");

	        	sandb_kill(sandb);}



		if((readwrite_permission == 1) && (config_permission[0] == 0))
		{ if((readwrite_permission == 1) && (config_permission[1] == 0))
                    { printf("Process terminated");
	 		sandb_kill(sandb);}
      		}
	       }

	 
	 if (regs.orig_rax == SYS_openat)

		{
		 char *config_permission = handle_call(sandb);
		 if (config_permission[2] == 0)
		 {
		   printf("Process terminated!!!");
                        sandb_kill(sandb);
		 } 	 
		}

	 if (regs.orig_rax == SYS_lstat)
		{
		 char *config_permission = handle_call(sandb);
		 printf("config_perm %s\n", config_permission[2]);
                 if (config_permission[2] == 0)
                 {
                   printf("Process terminated!!!");
                        sandb_kill(sandb);
                 }
  		}    		      		 
	
	 if (regs.orig_rax == SYS_stat)
                {
                 char *config_permission = handle_call(sandb);
                 if (config_permission[2] == 0)
                 {
                   printf("Process terminated!!!");
                        sandb_kill(sandb);
                 }
                }
 	 
    }
  }

}

char * handle_call(struct sandbox *sandb)
{
  int i;
  struct user_regs_struct regs;
  int read=0;
  char *val = malloc(4096);
  int allocated = 4096;
  unsigned long tmp;
  long orig_rax, rax;
  long buffer;
  int read_bit = 0;
  int read_permission = 1;
  int write_permission = 0;
  int readwrite_permission = 0;
  int exec_permission = 0;


  printf("System call called with " "%llu, %llu, %llu, %llu\n",regs.rbx, regs.rcx, regs.rdx, regs.rdi);
	while (1) 
  	{
    	 if (read + sizeof tmp > allocated) {
 	 allocated *= 2;
 	 val = realloc(val, allocated);
       			 }		

    	 tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs.rdi + read);
  	 if(errno != 0) {
	 val[read] = 0;
	 break;
			 }

	 memcpy(val + read, &tmp, sizeof tmp);
	 if (memchr(&tmp, 0, sizeof tmp) != NULL)
      	 break;
	 read += sizeof tmp;	
         printf ("%s\n", val);

  		/*char actualpath [PATH_MAX+1];
		char *ptr;
		ptr = realpath("check.txt", actualpath);
		printf("%s\n", ptr);*/

        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        char * final_permission = malloc(4096);
        int match;
	fp = fopen(config, "r");
        printf("%s\n", config);
    if (fp == NULL)
        exit(EXIT_FAILURE);
    while ((read = getline(&line, &len, fp)) != -1) {
        printf("Retrieved line of length %zu :\n", read);
        printf("%s", line);
  	char * pch;
  	printf ("Splitting string \"%s\" into tokens:\n",line);
  	pch = strtok (line," \t\n"); 	
	char * permission = pch;
    	printf ("permissions %s\n",permission);
   	pch = strtok (NULL, " \t\n");
	char * pattern = pch;
	printf ("pattern %s\n", pattern);
	char file[] = "readme.md";
	match = fnmatch ( pattern, val, 0);
	printf("fnmatch value %d\n", match);
	if(match == 0)

	{ final_permission = permission;
	  return final_permission; }

        fclose(fp);
        if (line)
        free(line);
       }
 }
}

void sandb_init(struct sandbox *sandb, int argc, char **argv) {
  pid_t pid;

  pid = fork();

  if(pid == -1)
    err(EXIT_FAILURE, "[SANDBOX] Error on fork:");

  if(pid == 0) {

    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_TRACEME:");

    if(execv(argv[0], argv) < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to execv:");

  } else {
    sandb->child = pid;
    sandb->progname = argv[0];
    wait(NULL);
  }
}

void sandb_run(struct sandbox *sandb) {
  int status;

  if(ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL) < 0) {
    if(errno == ESRCH) {
      waitpid(sandb->child, &status, __WALL | WNOHANG);
      sandb_kill(sandb);
    } else {
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
    }
  }

  wait(&status);

  if(WIFEXITED(status))
    exit(EXIT_SUCCESS);

  if(WIFSTOPPED(status)) {
    sandb_handle_syscall(sandb);
  }
}

int main(int argc, char **argv) {
  struct sandbox sandb;
  char * cwd;
  char fullpath[256];

  if(argc < 2) {
    errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
  }


  if(strcmp(argv[1],"-c") == 0 )

  {	config = argv[2];
	sandb_init(&sandb, argc-3, argv+3);

}

	else 
{

	char config_file[] = ".fendrc";

	if (access(config_file, F_OK)== 0 )

	{printf("found in curent\n");
	config = ".fendrc";
	sandb_init(&sandb, argc-1, argv+1);
}

	if ( access(config_file, F_OK) != 0 )

	{

	const char *name = "HOME";

	char *value;

	value = getenv(name);	

	char fullpath[256];

	sprintf(fullpath, "%s/%s", value, config_file);

	if( access(fullpath, F_OK) == 0)

	{sandb_init(&sandb, argc-1, argv+1);
	
	config = fullpath;
	}
	}

	if(access(fullpath, F_OK)!= 0 )

	{printf("Must provide a config file");
	
	errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);

	}

	}

  for(;;) {
    sandb_run(&sandb);
  }

  return EXIT_SUCCESS;
}
