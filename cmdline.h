#ifndef __TAYGA_CMDLINE_H__
#define __TAYGA_CMDLINE_H__


extern char *arg_conffile;
extern char *arg_user;
extern char *arg_group;
extern char *arg_pidfile;
extern int arg_do_mktun;
extern int arg_do_rmtun;
extern int arg_do_chroot;
extern int arg_detach;

void cmdline_parse(int argc, char **argv);

#endif
