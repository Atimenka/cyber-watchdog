#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <mntent.h>

static int save_to(const char *mnt, const char *data, size_t len) {
    char path[512]; snprintf(path,sizeof(path),"%s/cyber-watchdog-panic.log",mnt);
    mount(NULL,mnt,NULL,MS_REMOUNT,NULL);
    int fd=open(path,O_WRONLY|O_CREAT|O_APPEND,0644); if(fd<0)return -1;
    time_t now=time(NULL); dprintf(fd,"\n=== PANIC %smount: %s ===\n",ctime(&now),mnt);
    write(fd,data,len); dprintf(fd,"\n=== END ===\n"); fsync(fd); close(fd); return 0;
}

int main(void) {
    FILE *p=popen("dmesg -T 2>/dev/null||dmesg","r"); if(!p)return 1;
    char *buf=NULL; size_t len=0,cap=0; char line[1024];
    while(fgets(line,sizeof(line),p)){size_t ll=strlen(line);
        if(len+ll>=cap){cap=(cap+ll)*2+4096;buf=realloc(buf,cap);if(!buf){pclose(p);return 1;}}
        memcpy(buf+len,line,ll);len+=ll;} pclose(p); if(!buf)return 1;
    int saved=0; FILE *f=setmntent("/proc/mounts","r");
    if(f){struct mntent *m; while((m=getmntent(f))){
        if(!strcmp(m->mnt_type,"proc")||!strcmp(m->mnt_type,"sysfs")||!strcmp(m->mnt_type,"tmpfs")||!strcmp(m->mnt_type,"devtmpfs"))continue;
        if(save_to(m->mnt_dir,buf,len)==0)saved++;} endmntent(f);}
    fprintf(stderr,"[CW] %d saved\n",saved); free(buf); return saved>0?0:1;
}
