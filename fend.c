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
    {__NR_read, NULL},
    {__NR_write, NULL},
    {__NR_exit, NULL},
    {__NR_brk,  NULL},
    {__NR_mmap, NULL},
    {__NR_access,  NULL},
    {__NR_open, NULL},
    {__NR_fstat, NULL},
    {__NR_close, NULL},
    {__NR_mprotect, NULL},
    {__NR_munmap,  NULL},
    {__NR_arch_prctl,  NULL},
    {__NR_exit_group,  NULL},
    {__NR_getdents, NULL},
    {__NR_openat,  NULL},
    {__NR_stat,  NULL},
    {__NR_lstat,  NULL},
    {__NR_symlink, NULL},
    {__NR_unlink,  NULL},
    {__NR_link,  NULL},
};

char * config;
char *program_name;

void sandb_kill(struct sandbox *sandb) {
    kill(sandb->child, SIGKILL);
    wait(NULL);
    exit(EXIT_SUCCESS);
}

char *get_file_path(pid_t child, unsigned long addr){
    char *val = malloc(4096);
    int allocated = 4096;
    int read=0;
    unsigned long tmp;
    while (1) {
        if (read + sizeof tmp > allocated) {
            allocated *= 2;
            val = realloc(val, allocated);
        }
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if(errno != 0) {
            val[read] = 0;
            break;
        }
        memcpy(val + read, &tmp, sizeof tmp);
        if (memchr(&tmp, 0, sizeof tmp) != NULL)
        break;
        read += sizeof tmp;
    }
    return val;
}

void sandb_handle_syscall(struct sandbox *sandb) {
    int i;
    struct user_regs_struct regs;
    long orig_rax, rax;
    long buffer;
    int read_bit = 0;
    int readwrite_permission = 0;
    int exec_permission = 0;

    if(ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs) < 0)
        err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

    if (regs.orig_rax == SYS_execve)
    {   char *val;
        val = get_file_path(sandb->child, regs.rdi);
        char actualpath [PATH_MAX+1];
        char *ptr;
        realpath(val, actualpath);
        ptr = actualpath;
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        char * final_permission;
        int match;
        fp = fopen(config, "r");
        if (fp == NULL)
        exit(EXIT_FAILURE);
        while ((read = getline(&line, &len, fp)) != -1) {
            char * pch;
            pch = strtok (line," \t\n");
            char * permission = pch;
            pch = strtok (NULL, " \t\n");
            char * pattern = pch;
            match = fnmatch ( pattern, val, 0);
            if(match == 0)
            { final_permission = permission;
                if (final_permission[2] == '0')
                {printf("Terminating %s: unauthorized access of %s\n", program_name, val);
                sandb_kill(sandb);}
            }
        }
    }

    if (regs.orig_rax == __NR_open)
    {   char *val;
        val = get_file_path(sandb->child, regs.rdi);
        char actualpath [PATH_MAX+1];
        char *ptr;
        realpath(val, actualpath);
        ptr = actualpath;
        buffer = regs.rsi;
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        char * final_permission;
        int match;
        fp = fopen(config, "r");
        if (fp == NULL)
        exit(EXIT_FAILURE);
        while ((read = getline(&line, &len, fp)) != -1) {
            char * pch;
            pch = strtok (line," \t\n");
            char * permission = pch;
            pch = strtok (NULL, " \t\n");
            char * pattern = pch;
            int x = (buffer & O_CREAT);
            if(buffer & O_CREAT){
                char *lastSlash = NULL;
                char *parent = NULL;
                lastSlash = strrchr(ptr, '/'); // you need escape character
                lastSlash[0] = '\0';
                match = fnmatch(pattern, ptr, 0);
                if (match == 0)
                {char * final_permission = permission;
                    if (final_permission[1]=='0')
                    {printf("Terminating %s: unauthorized access of %s\n", program_name, ptr);
                    sandb_kill(sandb);}
                }
            }
            else
            {   int read_permission = 1;
                int write_permission = 0;
                if(buffer & O_WRONLY){
                    write_permission = 1;
                    read_permission = 0;
                }
                if(buffer & O_RDWR) {
                    write_permission = 1;
                    read_permission = 1;
                }
                match = fnmatch ( pattern, ptr, 0);
                if (match == 0)
                {   char * final_permission = permission;
                    if((read_permission == 1) && (final_permission[0] == '0'))
                    { printf("Terminating %s: unauthorized access of %s\n", program_name, ptr);
                    sandb_kill(sandb);}
                    if((write_permission == 1) && (final_permission[1] == '0'))
                    { 
                    printf("Terminating %s: unauthorized access of %s\n", program_name, ptr);
                    sandb_kill(sandb);}
                }
            }
        }
    }


    if (regs.orig_rax == SYS_lstat)
    {   char *val;
        val = get_file_path(sandb->child, regs.rdi);
        char actualpath [PATH_MAX+1];
        char *ptr;
        realpath(val, actualpath);
        ptr = actualpath;
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        char * final_permission = malloc(4096);
        int match;
        fp = fopen(config, "r");
        if (fp == NULL)
        exit(EXIT_FAILURE);
        while ((read = getline(&line, &len, fp)) != -1) {
            char * pch;
            pch = strtok (line," \t\n");
            char * permission = pch;
            pch = strtok (NULL, " \t\n");
            char * pattern = pch;
            match = fnmatch ( pattern, ptr, 0);
            if(match == 0)
            { final_permission = permission;
                if (final_permission[2] == '0')
                {   printf("Terminating %s: unauthorized access of %s\n", program_name, ptr);
                    sandb_kill(sandb);}
                fclose(fp);
            }
        }
    }

    if (regs.orig_rax == SYS_creat)
    {   char *val;
        val = get_file_path(sandb->child, regs.rdi);
        char actualpath [PATH_MAX+1];
        char *ptr;
        realpath(val, actualpath);
        ptr = actualpath;
        char *lastSlash = NULL;
        char *parent = NULL;
        lastSlash = strrchr(ptr, '/'); // you need escape character
        lastSlash[0] = '\0';
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        char * final_permission = malloc(4096);
        int match;
        fp = fopen(config, "r");
        if (fp == NULL)
        exit(EXIT_FAILURE);
        while ((read = getline(&line, &len, fp)) != -1) {
            char * pch;
            pch = strtok (line," \t\n");
            char * permission = pch;
            pch = strtok (NULL, " \t\n");
            char * pattern = pch;
            match = fnmatch ( pattern, ptr, 0);
            if(match == 0)
            { final_permission = permission;
                if (final_permission[2] == '0')
                {   printf("Terminating %s: unauthorized access of %s\n", program_name, ptr);
                    sandb_kill(sandb);}
            }
        }
    }

    if(regs.orig_rax == SYS_symlink)
    {   char *val;
        val = get_file_path(sandb->child, regs.rsi);
        char actualpath [PATH_MAX+1];
        char *ptr;
        realpath(val, actualpath);
        ptr = actualpath;
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        char * final_permission = malloc(4096);
        int match;
        fp = fopen(config, "r");
        if (fp == NULL)
        exit(EXIT_FAILURE);
        while ((read = getline(&line, &len, fp)) != -1) {
            char * pch;
            pch = strtok (line," \t\n");
            char * permission = pch;
            pch = strtok (NULL, " \t\n");
            char * pattern = pch;
            char *lastSlash = NULL;
            char *parent = NULL;
            lastSlash = strrchr(ptr, '/'); // you need escape character
            lastSlash[0] = '\0';
            match = fnmatch ( pattern, ptr, 0);
            if(match == 0)
            { final_permission = permission;
                if(final_permission[1] == '0')
                {printf("Terminating %s: unauthorized access of %s\n", program_name, ptr);
                sandb_kill(sandb);}
            }
        }
    }

    if (regs.orig_rax == SYS_mkdir)
{	
        FILE * fp;

        char * line = NULL;

        size_t len = 0;

        ssize_t read;

        char * final_permission = malloc(4096);

        int match;

        fp = fopen(config, "r");


        if (fp == NULL)

        exit(EXIT_FAILURE);

        while ((read = getline(&line, &len, fp)) != -1) {


            char * pch;

            printf ("Splitting string %s into tokens:\n",line);

            pch = strtok (line," \t\n");

            char * permission = pch;


            pch = strtok (NULL, " \t\n");

            char * pattern = pch;


            char *lastSlash = NULL;

            char *parent = NULL;

         char actualpath [PATH_MAX+1];

        char *ptr;
	char* val;

        val = get_file_path(sandb->child, regs.rdi);


        realpath(val, actualpath);

        ptr = actualpath;

           lastSlash = strrchr(ptr, '/'); // you need escape character

            lastSlash[0] = '\0';
	    printf("11pattern %s\n", pattern);
	    printf("22ptr %s\n", ptr);

            match = fnmatch ( pattern, ptr, 0);


            if(match == 0)

            { final_permission = permission;


                if(final_permission[1] == '0')

                {printf("Terminating %s: unauthorized access of %s\n", program_name, ptr);

                sandb_kill(sandb);}

            }

        }

    }

    if (regs.orig_rax == SYS_rename)
    {   char *val;
        val = get_file_path(sandb->child, regs.rdi);
        char actualpath [PATH_MAX+1];
        char *ptr;
        realpath(val, actualpath);
        ptr = actualpath;
        buffer = regs.rsi;
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        char * final_permission;
        int match;
        fp = fopen(config, "r");
        if (fp == NULL)
        exit(EXIT_FAILURE);
        while ((read = getline(&line, &len, fp)) != -1) {
            char * pch;
            pch = strtok (line," \t\n");
            char * permission = pch;
            pch = strtok (NULL, " \t\n");
            char * pattern = pch;
            int x = (buffer & O_CREAT);
            char *lastSlash = NULL;
            char *parent = NULL;
            lastSlash = strrchr(ptr, '/'); // you need escape character
            lastSlash[0] = '\0';
            match = fnmatch(pattern, ptr, 0);
            if (match == 0)
            {char * final_permission = permission;
                if (final_permission[1]=='0')
                {printf("Terminating %s: unauthorized access of %s\n", program_name, ptr);
                sandb_kill(sandb);}
            }
        }
    }

    if (regs.orig_rax == SYS_link)
    {
        char *val;
        val = get_file_path(sandb->child, regs.rsi);
        char actualpath [PATH_MAX+1];
        char *ptr;
        realpath(val, actualpath);
        ptr = actualpath;
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        char * final_permission = malloc(4096);
        int match;
        fp = fopen(config, "r");
        if (fp == NULL)
        exit(EXIT_FAILURE);
        while ((read = getline(&line, &len, fp)) != -1) {
            char * pch;
            pch = strtok (line," \t\n");
            char * permission = pch;
            pch = strtok (NULL, " \t\n");
            char * pattern = pch;
            char *lastSlash = NULL;
            char *parent = NULL;
            lastSlash = strrchr(ptr, '/'); // you need escape character
            lastSlash[0] = '\0';
            match = fnmatch ( pattern, ptr, 0);
            if(match == 0)
            { final_permission = permission;
                if(final_permission[1] == '0')
                {printf("Terminating %s: unauthorized access of %s\n", program_name, ptr);
                sandb_kill(sandb);}
            }
        }
    }

    if (regs.orig_rax == SYS_unlink)
    {   char *val;
        val = get_file_path(sandb->child, regs.rdi);
        char actualpath [PATH_MAX+1];
        char *ptr;
        realpath(val, actualpath);
        ptr = actualpath;
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        char * final_permission = malloc(4096);
        int match;
        fp = fopen(config, "r");
        if (fp == NULL)
        exit(EXIT_FAILURE);
        while ((read = getline(&line, &len, fp)) != -1) {
            char * pch;
            pch = strtok (line," \t\n");
            char * permission = pch;
            pch = strtok (NULL, " \t\n");
            char * pattern = pch;
            char *lastSlash = NULL;
            char *parent = NULL;
            lastSlash = strrchr(ptr, '/'); // you need escape character
            lastSlash[0] = '\0';
            match = fnmatch ( pattern, ptr, 0);
            if(match == 0)
            { final_permission = permission;
                if(final_permission[1] == '0')
                {printf("Terminating %s: unauthorized access of %s\n", program_name, ptr);
                sandb_kill(sandb);}
            }
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
    program_name = argv[0];
    if(argc < 2) {
        errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
    }
    if(strcmp(argv[1],"-c") == 0 )
    {   config = strdup(argv[2]);
        sandb_init(&sandb, argc-3, argv+3);
    }
    else
    {   char config_file[] = ".fendrc";
        if (access(config_file, F_OK)== 0 )
        {   printf("found in curentn");
            config = strdup(".fendrc");
            sandb_init(&sandb, argc-1, argv+1);
        }
        else{
            if ( access(config_file, F_OK) != 0 )
            {   const char *name = "HOME";
                char *value;
                value = getenv(name);
                char fullpath[256];
                sprintf(fullpath, "%s/%s", value, config_file);
                if( access(fullpath, F_OK) == 0)
                {   sandb_init(&sandb, argc-1, argv+1);
                    config = strdup(fullpath);
                }
                else
                {   printf("Must provide a config file");
                    errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
                }
            }
        }
    }
    for(;;) {
        sandb_run(&sandb);
    }
    return EXIT_SUCCESS;
}
