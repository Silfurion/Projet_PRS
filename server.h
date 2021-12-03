int main();
int create_socket(sockaddr_in* , int ) ;
void wait_client(fd_set* , timeval* , int* , int*, int* , int*);
void gestion_client_fork(int* , int* , sockaddr_in* , int ,sockaddr_storage* , socklen_t*);
void reconnaissance_DATA(int*,int*,unsigned char*,char*,int*);
