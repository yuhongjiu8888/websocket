/*
function:websocket-server
author : jackyu
date   : 2020-05-16
mail   : yuhongiu@foxmail.com
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>


#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>


#define BUFFER_SIZE 1024
#define ERROR       -1
#define SUCCESS     0
#define JACK_PORT   8888

const char* key =  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";  //key

//数据包结构
typedef struct _frame_head {
    char fin;
    char opcode;
    char mask;
    unsigned long long payload_length;
    char masking_key[4];
} frame_head;




int init_server()
{
    int server_fd;

    //初始化socket
    server_fd = socket(AF_INET,SOCK_STREAM,0);
    if(server_fd < 0)
    {
        printf("socket create error![%s][%d]\n",__FILE__,__LINE__);
        return ERROR;
    }
    printf("socket create success![%s][%d]\n",__FILE__,__LINE__);

    //重置socket结构
    struct sockaddr_in saddr;
    memset(&saddr,0x00,sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(JACK_PORT);
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);


    //bind socket

    if( bind(server_fd,(struct sockaddr*)&saddr,sizeof(struct sockaddr) ) < 0)
    {
        printf("socket bind error![%s][%d]\n",__FILE__,__LINE__);
        return ERROR;
    }
    printf("socket bind success![%s][%d]\n",__FILE__,__LINE__);

    //listen socket
    if( listen(server_fd,5) < 0 )
    {
        printf("socket listen error![%s][%d]\n",__FILE__,__LINE__);
        return ERROR;
    }
    printf("socket listen success![%s][%d]\n",__FILE__,__LINE__);


    return server_fd;

}

void setnonblocking(int sock)
{
    int opts;
    opts=fcntl(sock,F_GETFL);
    if(opts < 0)
    {
        printf("fnct error\n");
        exit -1;
    }

    opts = opts|O_NONBLOCK;

    if(fcntl(sock,F_SETFL,opts)<0)
    {
        printf("fcntl(sock,SETFL,opts)\n");
        exit -1;
    }
}

//epoll 注册
void ep_add(int epollfd,int fd,struct epoll_event ev)
{
    epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
}

//epoll 修改
void ep_mod(int epollfd,int fd,struct epoll_event ev)
{
    epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev);
}

//epoll 删除
void ep_del(int epollfd,int fd,struct epoll_event ev)
{
    epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev);
}


/*逐行读取函数
握手函数循环调用，每次获得一行字符串，返回下一行开始位置*/
int _readline(char* allbuf,int level,char* linebuf)
{
    int len = strlen(allbuf);
    for (;level<len;++level)
    {
        if(allbuf[level]=='\r' && allbuf[level+1]=='\n')
            return level+2;
        else
            *(linebuf++) = allbuf[level];
    }
    return -1;
}


int base64_encode(char *in_str, int in_len, char *out_str)
{
    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    size_t size = 0;

    if (in_str == NULL || out_str == NULL)
        return -1;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, in_str, in_len);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bptr);
    memcpy(out_str, bptr->data, bptr->length);
    out_str[bptr->length-1] = '\0';
    size = bptr->length;

    BIO_free_all(bio);
    return size;
}




int shakehands(int cli_fd)
{
    //next line's point num
    int level = 0;
    //all request data
    char buffer[BUFFER_SIZE];
    //a line data
    char linebuf[256];
    //Sec-WebSocket-Accept
    char sec_accept[32];
    //sha1 data
    unsigned char sha1_data[SHA_DIGEST_LENGTH+1]={0};
    //reponse head buffer
    char head[BUFFER_SIZE] = {0};

    if (read(cli_fd,buffer,sizeof(buffer))<=0)
        printf("read error [%s][%d] \n",__FILE__,__LINE__);
    printf("request\n");
    printf("%s\n",buffer);

    do {
        memset(linebuf,0,sizeof(linebuf));
        level = _readline(buffer,level,linebuf);
        //printf("line:%s\n",linebuf);

        if (strstr(linebuf,"Sec-WebSocket-Key")!=NULL)
        {
            strcat(linebuf,key);
//            printf("key:%s\nlen=%d\n",linebuf+19,strlen(linebuf+19));
            SHA1((unsigned char*)&linebuf+19,strlen(linebuf+19),(unsigned char*)&sha1_data);
//            printf("sha1:%s\n",sha1_data);
            base64_encode(sha1_data,strlen(sha1_data),sec_accept);
//            printf("base64:%s\n",sec_accept);
            /* write the response */
            sprintf(head, "HTTP/1.1 101 Switching Protocols\r\n" \
                          "Upgrade: websocket\r\n" \
                          "Connection: Upgrade\r\n" \
                          "Sec-WebSocket-Accept: %s\r\n" \
                          "\r\n",sec_accept);

            printf("response\n");
            printf("%s",head);
            if (write(cli_fd,head,strlen(head))<0)
                printf("write error [%s][%d] \n",__FILE__,__LINE__);

            break;
        }
    }while((buffer[level]!='\r' || buffer[level+1]!='\n') && level!=-1);
    return 0;
}


/**
 * @brief umask
 * xor decode
 * @param data 传过来时为密文，解码后的明文同样存储在这里
 * @param len data的长度
 * @param mask 掩码
 */
void umask(char *data,int len,char *mask)
{
    int i;
    for (i=0;i<len;++i)
        *(data+i) ^= *(mask+(i%4));
}


/**
字符串反转函数
用于解决大端小端问题
**/
void inverted_string(char *str,int len)
{
    int i; char temp;
    for (i=0;i<len/2;++i)
    {
        temp = *(str+i);
        *(str+i) = *(str+len-i-1);
        *(str+len-i-1) = temp;
    }
}


int recv_frame_head(int fd,frame_head* head)
{
    char one_char;
    /*read fin and op code*/
    if (read(fd,&one_char,1)<=0)
    {
        printf("read fin\n");
        return -1;
    }
    head->fin = (one_char & 0x80) == 0x80;
    head->opcode = one_char & 0x0F;
    if (read(fd,&one_char,1)<=0)
    {
        printf("read mask \n");
        return -1;
    }
    head->mask = (one_char & 0x80) == 0X80;

    /*get payload length*/
    head->payload_length = one_char & 0x7F;

    if (head->payload_length == 126)
    {
        char extern_len[2];
        if (read(fd,extern_len,2)<=0)
        {
            printf("read extern_len \n");
            return -1;
        }
        head->payload_length = (extern_len[0]&0xFF) << 8 | (extern_len[1]&0xFF);
    }
    else if (head->payload_length == 127)
    {
        char extern_len[8];
        if (read(fd,extern_len,8)<=0)
        {
            printf("read extern_len \n");
            return -1;
        }
        inverted_string(extern_len,8);
        memcpy(&(head->payload_length),extern_len,8);
    }

    /*read masking-key*/
    if (read(fd,head->masking_key,4)<=0)
    {
        printf("read masking-key \n");
        return -1;
    }

    return 0;
}


int send_frame_head(int fd,frame_head* head)
{
    char *response_head;
    int head_length = 0;
    if(head->payload_length<126)
    {
        response_head = (char*)malloc(2);
        response_head[0] = 0x81;
        response_head[1] = head->payload_length;
        head_length = 2;
    }
    else if (head->payload_length<0xFFFF)
    {
        response_head = (char*)malloc(4);
        response_head[0] = 0x81;
        response_head[1] = 126;
        response_head[2] = (head->payload_length >> 8 & 0xFF);
        response_head[3] = (head->payload_length & 0xFF);
        head_length = 4;
    }
    else
    {
        response_head = (char*)malloc(12);
        response_head[0] = 0x81;
        response_head[1] = 127;
        memcpy(response_head+2,head->payload_length,sizeof(unsigned long long));
        inverted_string(response_head+2,sizeof(unsigned long long));
        head_length = 12;
    }

    if(write(fd,response_head,head_length)<=0)
    {
        printf("write head \n");
        return -1;
    }

    free(response_head);
    return 0;
}



int main()
{
    printf("websocket server start![%s][%d]\n",__FILE__,__LINE__);


    //epoll io
    struct epoll_event ev,events[512];
    int epoll_fd;
    epoll_fd = epoll_create(1); //size 大于 1 即可
    if(epoll_fd < 0)
    {
        printf("epoll_fd create  error![%s][%d]\n",__FILE__,__LINE__);
        return ERROR;
    }

    int serverfd = init_server();
    setnonblocking(serverfd);   //设置非阻塞

    ev.data.fd = serverfd;
    ev.events = EPOLLIN; //水平触发

    //注册epoll事件
    ep_add(epoll_fd,serverfd,ev);

    while(1)
    {
        int ready = epoll_wait(epoll_fd,events,512,0);
        if(ready <= 0)
        {
            //printf("no event contitue\n");
            continue;
        }

        int i;
        for(i = 0;i < ready; i++)
        {
            if(events[i].data.fd == serverfd )
            {
                struct sockaddr_in clientaddr;
                size_t cli_len = sizeof(clientaddr);
                int connfd = accept(serverfd,(struct sockaddr *)&clientaddr, &cli_len);
                if(connfd < 0)
                {
                    printf("accept new client error![%s][%d]\n",__FILE__,__LINE__);
                    continue;   
                }
                printf("accept new client success come from [%s]!\n",inet_ntoa(clientaddr.sin_addr));
                ev.data.fd = connfd;
                ev.events = EPOLLIN | EPOLLET; //水平触发
                ep_add(epoll_fd,connfd,ev);
                
            }
            else if(events[i].events&EPOLLIN)
            {
                int conn = events[i].data.fd;
                printf("deal [%d] data!\n",conn);
                shakehands(conn);
                frame_head head;
                int rul = recv_frame_head(conn,&head);
                if( rul < 0)
                    continue;
                send_frame_head(conn,&head);
                char payload_data[1024] = {0};
                int size = 0;
                do {
                        int rul;
                        rul = read(conn,payload_data,1024);
                        if (rul<=0)
                            break;
                        size+=rul;

                        umask(payload_data,size,head.masking_key);
                        printf("recive:%s\n",payload_data);

                        if (write(conn,payload_data,rul)<=0)
                            break;
                }while(size<head.payload_length);
                printf("\n-----------\n");
                
            }
        }
 

    }


    printf("websocket server end![%s][%d]\n",__FILE__,__LINE__);
    return 0;

}
