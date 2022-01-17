#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>

//#include "my_malloc.h"

#define MAX_GRP 1001

#define err_abort(x) do { \
      if (!(x)) {\
         fprintf(stderr, "Fatal error: %s:%d: ", __FILE__, __LINE__);   \
         perror(""); \
         exit(1);\
      }\
   } while (0)

void print_escaped(FILE *fp, const char* buf, unsigned len) {
   long i;
   for (i=0; i < len; i++) {
      if (isprint(buf[i])) {
         if (buf[i] == '\\')
            fputc(buf[i], fp);
         fputc(buf[i], fp);
      }
      else fprintf(fp, "\\x%02hhx", buf[i]);
   }
}

// Simplified password checking against a hard-coded list
char *valid_logins[] = {
   "couchpotato_smith",
   "sweetpotato_smyth",
   "mashedpotato_smythereen",
   0
};

long chkPw(char *cred, char *db_entry);
unsigned min_usize;
/************ Function vulnerable to buffer overflow on stack ***************/

long auth(char *uname, long ulen, char* pass, long plen) {
  char *cred; // ***-0x10
  unsigned bufsz; // ***-0x1c
  char **db = valid_logins; // ***-0x18

  if (ulen <= min_usize) // BUG: condition is reversed, so the bcopy below
     bufsz = ulen;       // can result in a buffer overflow.
  else bufsz = min_usize;
  bufsz += plen+1;

  cred = alloca(bufsz);
  bcopy(pass, cred, plen);
  cred[plen] = '_';
  bcopy(uname, &cred[plen+1], ulen); // possible buffer overflow.

  if (plen == 0 || ulen == 0) return 0;
  while (*db)
     if (chkPw(cred, *db))
        return 1; 
     else db++;

  return 0;
}

long login_attempts;
char *s1 = "/bin/ls";
char *s2 = "/bin/false";
void g(char *uname, long ulen, char* pass, long plen) {
  long authd=0;
  long a=5, b=6;
  authd = auth(uname, ulen, pass, plen);

  if (authd) {
     // Successfully authenticated, now provide service: List current directory
     fprintf(stdout, "Authentication succeeded, here is your output\n");
     execl(s1, "ls", NULL);
  }
  else { // Authentication failure
     fprintf(stdout, "Login denied. ");
     if (login_attempts++ > 3) {
        fprintf(stdout, "Too many failures, aborting session");
        err_abort(execl(s2, "false", NULL)>=0); // a program that prints an error
     }
     else fprintf(stdout, "Try again");
     fflush(stdout);
  }
}

#ifndef ASM_ONLY
void padding() {
int i, z;
#include "padding.h"
}
#endif

long main_loop(unsigned seed) {
   long nread;
   char *user=NULL, *pass=NULL;
   unsigned ulen=0, plen=0;

   srandom(seed-990);
   unsigned rdbufsz = LEN1 + (random() % LEN1);
   char *rdbuf = (char*)alloca(rdbufsz);
   alloca(((unsigned)random()) % LEN1);
   fprintf(stdout, "Welcome");
   fflush(stdout);
   do {
      err_abort((nread = read(0, rdbuf, rdbufsz-1)) >= 0);
      if (nread == 0) {
         fprintf(stdout, "Unexpected read error: quitting");
         fflush(stdout);
         return 0;
      }
      rdbuf[nread] = '\0'; // null-terminate
      switch (rdbuf[0]) {

      case 'e': // echo command: e <string_to_echo>
         printf(&rdbuf[2]);
         fflush(stdout);
         break;

      case 'u': // provide username
         fprintf(stdout, "User received");
         fflush(stdout);
         ulen = nread-3; // skips last char
         user = (char*)malloc(ulen);
         bcopy(&rdbuf[2], user, ulen);
         break;

      case 'p': // provide password
         fprintf(stdout, "Password received");
         fflush(stdout);
         pass = (char*)malloc(plen);
         plen = nread-3;
         bcopy(&rdbuf[2], pass, plen);
         break;

      case 'l': { // login using previously supplied username and password
         if (user != NULL && pass != NULL) {
            g(user, ulen, pass, plen);
            free(pass);
            free(user);
            user=pass=NULL;
            ulen=0; plen=0;
         }
         else {
           fprintf(stdout, "vuln: Use u and p commands before logging in");
           fflush(stdout);
         }
         break;
      }

      case 'q':
         fprintf(stdout, "vuln: quitting\n");
         return 0;

      default:
         fprintf(stdout, "vuln: Invalid operation. Valid commands are:\n");
         fprintf(stdout, "\te <data>: echo <data>\n");
         fprintf(stdout, "\tu <user>: enter username\n");
         fprintf(stdout, "\tp <pass>: enter password\n");
         fprintf(stdout, 
                 "\tl: login using previously provided username/password\n");
         fprintf(stdout, "\tq: quit");
         fflush(stdout);
         break;
      }
   } while (1);
}

int main(int argc, char *argv[]) {
   unsigned minbufsz();
   min_usize = minbufsz();

   if(argc < 2) {
      fprintf(stderr, "Not enough arguments\n");
      exit(0);
   }
   unsigned seed = atoi(argv[1]);
   if (seed > MAX_GRP) {
      fprintf(stderr, "Usage: %s <group_id>\n", argv[0]);
      fprintf(stderr, "<group_id> must be between 0 and %d\n", MAX_GRP);
      exit(1);
   }
   do {
      int pid = fork();
      if (pid == 0)
        return main_loop(seed);
      else {
        int status;
        wait(&status);
        if (status == 0)
          return 0;
      }
   } while(1);
};

unsigned minbufsz() {
   return LEN2 + (random() % LEN2);
};

long chkPw(char *cred, char *db_entry) {
   return (strncmp(cred, db_entry, strlen(db_entry)) == 0);
}

char d[128];
void private_helper(int a, long b, char* c) {
   strcpy(d, c);
   fprintf(stdout, "**** private_helper(0x%x, 0x%lx, %p \"%s\") called", 
           a, b, c, d);
   fflush(stdout);
}

void private_helper2() {
   fprintf(stdout, "*********** private_helper2 called!\n");
   fflush(stdout);
}

