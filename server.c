#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>

#define RCVSIZE 1500



int create_socket(struct sockaddr_in *adresse_control , int port) {
  int valid = 1  ; 
  int server_desc_control = socket(AF_INET, SOCK_DGRAM, 0);
  if (server_desc_control < 0) {
    perror("Cannot create socket\n");
    return -1;
  }
  setsockopt(server_desc_control, SOL_SOCKET, SO_REUSEADDR, &valid, sizeof(int));

  adresse_control->sin_family= AF_INET;
  adresse_control->sin_port= htons(port);
  adresse_control->sin_addr.s_addr= htonl(INADDR_ANY);
  if (bind(server_desc_control, (struct sockaddr*) adresse_control, sizeof(*adresse_control)) == -1) {
    perror("Bind failed\n");
    close(server_desc_control);
    return -1;
  }
  return server_desc_control ;  

}


void wait_client(fd_set *readset , struct timeval *tv , int *pid_process , int *port_client_utilises , int *result_select , int *return_child ){

    do{
      FD_SET(3 , readset);
      *result_select = select(4, readset , NULL , NULL , tv); 
      *return_child = waitpid(-1 ,NULL,WNOHANG) ;
      if(*return_child != 0 && *return_child != -1 ) {
        for ( int j = 0 ; j<10*sizeof(int)/sizeof(int) ; j++) {
          if(pid_process[j] == *return_child){
            port_client_utilises[j] = 0 ;
            pid_process[j] = 0 ;
            printf("pid_process : %i\n", pid_process[j]);
            break ; 

          }
        }

      }

    }while(*result_select == 0 );
  }



void reconnaissance_DATA(int *sequence,int *sequence_ACK_2 , unsigned char *DATA_char , char *buffer_message , int *nombre_ACK_succ){
  char *ret_ACK ;  
  ret_ACK = strstr(buffer_message , "ACK");
  char result[6];
  if(ret_ACK != NULL){
    sscanf(ret_ACK , " %*c %*c %*c %6s" , result);
      //printf("Atoi result : %i \n", atoi(result));
    if(*sequence_ACK_2 == atoi(result)){
      *nombre_ACK_succ++ ; 
    }
    if(atoi(result) >= *sequence_ACK_2){
      //printf("resultats : %s \n", result);
      *sequence_ACK_2 = atoi(result)+1;
    }
  }

}

void gestion_client_fork(int *server_desc_control , int *server_desc_message , struct sockaddr_in *adresse_message , int port , struct sockaddr_storage *serverStorage , socklen_t addr_size ) {

  time_t start_t,end_t; 
  start_t = time(NULL);
  socklen_t addr_size2 = sizeof(struct sockaddr_in);
  long double file_size ; 
  struct timeval tv,RTT_start,RTT_end;
  tv.tv_sec = 0; 
  tv.tv_usec = 0 ; 
  int result_select ;
  fd_set readset ; 
  FILE *fp = (FILE *)malloc(sizeof(FILE));
  unsigned char DATA_char[RCVSIZE-6];
  char *sequence_char = (char *)malloc(6*sizeof(char));
  char buffer_message[RCVSIZE]; 
  int sequence = 1 ;
  int sequence_ACK_2 = 0;
  int message ; 
  int NO_STOP =1 ;
  int error ; 
  int size ; 
  int compt = 0 ; 
  int RTT = 300 ;
  int security_factor = 0;
  int window = 5 ; 
  int fils_gestion_ack;
  int nombre_ACK_succ = 0;
  close(*server_desc_control);
  sprintf(sequence_char,"%06i",sequence);
  printf("socket :   %i \n",*server_desc_message);


  memset(buffer_message,0,RCVSIZE);
  message = recvfrom(*server_desc_message,buffer_message,RCVSIZE,0,(struct sockaddr *)adresse_message,&addr_size2);
  if(message == -1){
    printf("Error \n");
  }
  fp = fopen(buffer_message,"rb");
  printf("server_desc_message : %i \n",*server_desc_message);
  memset(buffer_message, 0 , RCVSIZE); 
  strcpy((char * )buffer_message,sequence_char);
  size = fread(buffer_message+6,1,RCVSIZE-6,fp);
  do{
    FD_SET(4 , &readset); 
    tv.tv_sec = 0 ;
    tv.tv_usec = 500000 ; 
    printf("Size : %i \n", size);
    gettimeofday(&RTT_start,NULL);
    error = sendto(*server_desc_message,buffer_message,size+6,0,(struct sockaddr * )adresse_message , addr_size2);
    result_select = select(5, &readset , NULL , NULL , &tv); 
  }while(result_select == 0);
  message = recvfrom(*server_desc_message,buffer_message,RCVSIZE,0,(struct sockaddr *)adresse_message,&addr_size2);
  gettimeofday(&RTT_end,NULL);
  printf("RTT_start : %li , RTT_end : %li  difference : %li\n",RTT_start.tv_usec , RTT_end.tv_usec,RTT_end.tv_usec-RTT_start.tv_usec);
  RTT = (RTT_end.tv_usec - RTT_start.tv_usec);
  RTT = (int)(RTT+security_factor*RTT);
  printf("RTT : %i \n",RTT);
  sequence = sequence+1;
  sprintf(sequence_char,"%06i",sequence);


  do{
    for(int i = 0 ; i<window ; i++ ){
      memset(buffer_message, 0 , RCVSIZE);  
      strcpy((char * )buffer_message,sequence_char);
      size = fread(buffer_message+6,1,RCVSIZE-6,fp);
      FD_SET(4 , &readset);
      tv.tv_sec = 0 ;
      tv.tv_usec = 4000 ; 
      if( size != RCVSIZE-6 ){
        NO_STOP =0 ;
        i = window;
      }
      else{ 
        error = sendto(*server_desc_message,buffer_message,RCVSIZE,0,(struct sockaddr * )adresse_message , addr_size2);
        //printf("Numéro de séquence : %s\n", sequence_char);
        sequence = sequence+1;
        sprintf(sequence_char,"%06i",sequence);
      }
    }
    usleep(RTT);
    result_select = select(5, &readset , NULL , NULL , &tv); 
    while(result_select != 00){
      memset(buffer_message , 0 , RCVSIZE);
      message = recvfrom(*server_desc_message,buffer_message,RCVSIZE,0,(struct sockaddr *)adresse_message,&addr_size2);
      reconnaissance_DATA(&sequence , &sequence_ACK_2 , DATA_char , buffer_message , &nombre_ACK_succ);
      //printf("Numéro sequence : %i \n",sequence_ACK_2);
      fseek(fp,(RCVSIZE-6)*(sequence_ACK_2-1),SEEK_SET);
      sequence = sequence_ACK_2;
      FD_SET(4 , &readset);
      tv.tv_sec = 0 ;
      tv.tv_usec = 4000 ;
      result_select = select(5, &readset , NULL , NULL , &tv); 
      sprintf(sequence_char,"%06i",sequence);
      compt++ ; 
  }
      if(compt == window){
            window = (int)window*2;
          }
          else{
            if(window > 5){
              window = window/2 ;
            }
            else{
              window = 5 ; 
            }
          }
          compt = 0 ; 
  }while(NO_STOP == 1);
    fseek(fp,(RCVSIZE-6)*(sequence_ACK_2-1),SEEK_SET);
    memset(buffer_message, 0 , RCVSIZE);
    strcpy((char * )buffer_message,sequence_char);
    size = fread(buffer_message+6,1,RCVSIZE-6,fp);
    do{
      FD_SET(4 , &readset); 
      tv.tv_sec = 0 ;
      tv.tv_usec = 6000 ; 
      printf("Size : %i \n", size);
      error = sendto(*server_desc_message,buffer_message,size+6,0,(struct sockaddr * )adresse_message , addr_size2);
      result_select = select(5, &readset , NULL , NULL , &tv); 
    }while(result_select == 0);
    memset(buffer_message, 0 , RCVSIZE);
    strcpy((char *)buffer_message,"FIN");
    error = sendto(*server_desc_message,buffer_message,3,0,(struct sockaddr * )adresse_message , addr_size2);
    if(error == -1){
      printf("Error \n");
    }
    close(*server_desc_message); 
    end_t = time(NULL);
    fseek(fp , 0 , SEEK_END);
    file_size = ftell(fp);
    fclose(fp); 
    printf("start_t : %li    end_t : %li  CLOCKS_PER_SEC : %li , f_size : %Lf \n",start_t , end_t , CLOCKS_PER_SEC,file_size*0.000001);
    long double t = (long double)(end_t - start_t);
    printf("Le temps : %Lf \n", t);
    printf("Débit = %Lf  Mo/sec\n",(long double)(file_size*0.000001)/t);
    printf("RTT = %i\n",RTT);
    printf("BYE \n");
    exit(0);

}

int main (int argc, char *argv[]) {
if(argc == 2)
  {
    int *port_client_utilises = (int *)malloc(10*sizeof(int)) ;
    memset(port_client_utilises, 0 ,10*sizeof(int));
    int *pid_process = (int *)malloc(10*sizeof(int));
    memset(pid_process,0,10*sizeof(int)); 
    struct sockaddr_in adresse_control , adresse_message ;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size = sizeof(serverStorage);
    int port = 5001;
    if(atoi(argv[1]) != 0){
      port = atoi(argv[1]);
    }
    else{
      perror("Invalid Input \n");
      return -1;
    }
    char buffer_control[RCVSIZE];

    //create socket
    int server_desc_control = create_socket(&adresse_control , port);
    printf("server_desc_control : %i \n", server_desc_control);

//////Initialisation ///////////////////////////////////////////////////



    fd_set readset ; 
    struct timeval tv;
    tv.tv_sec = 0; 
    tv.tv_usec = 0 ; 
    struct timeval tv_SYN_ACK;
    tv_SYN_ACK.tv_sec = 1; 
    tv_SYN_ACK.tv_usec = 0 ; 
    srand(time(NULL)); 
    int result_select ;   
    int new_Port ; 
    int return_child ; 
    int message ; 
    char PORT[RCVSIZE];
    char result[6];
    int NO_STOP = 1 ; 



///////////////////////////////////////////////////////////////////////



    printf("%i \n", server_desc_control);
    while(NO_STOP){



////////////////////////////// Arrivée Client //////////////////////////////////////////////////////////////
      
      printf("recv \n");
      wait_client(&readset , &tv , pid_process ,port_client_utilises, &result_select ,&return_child);
      message = recvfrom(server_desc_control,buffer_control,RCVSIZE,0,(struct sockaddr *)&adresse_control,&addr_size);
      printf("Message_error : %i \n",message);
      printf("%s \n",buffer_control);

      if(strstr(buffer_control , "SYN") != NULL){

          sscanf(buffer_control , "%*c %*c %*c %6s", result);
        
      }
      if(strstr(buffer_control , "stop serveur") != NULL)
      {
        NO_STOP = 0 ;
        continue;
      }
      else
      {
            printf("%s \n",buffer_control);
            memset(buffer_control,0,RCVSIZE);

            strcpy(buffer_control,"SYN-ACK");
            for(int i = 0 ; i< 10*sizeof(int)/sizeof(int) ; i ++){
              printf(" port client : %i \n", port_client_utilises[i]);
              if(port_client_utilises[i] == 0){
                new_Port = port+1+i ; 
                break;
              }
            }
            int server_desc_message = create_socket(&adresse_message , new_Port);
            printf("server_desc_message : %i\n",server_desc_message );
            int gestion_client = fork();
            if (gestion_client == 0 ){
                gestion_client_fork( &server_desc_control , &server_desc_message, &adresse_message , new_Port , &serverStorage , addr_size);
            }
            else{
              close(server_desc_message);
              sprintf(PORT,"%i",new_Port);
              strcat(buffer_control,PORT);
              printf("%s\n",buffer_control);
              do{
                tv_SYN_ACK.tv_sec = 4 ;
                printf("la socket : %i \n", server_desc_control);
                FD_SET(3 , &readset); 
                sendto(server_desc_control,buffer_control,12,0,(struct sockaddr *)&adresse_control,addr_size);
                result_select = select(4, &readset , NULL , NULL , &tv_SYN_ACK);
                printf("Send SYN_ACK until recieve ACK \n");
              }while(result_select == 0); 
              memset(buffer_control,0,RCVSIZE);
              message = recvfrom(server_desc_control,buffer_control,RCVSIZE,0,(struct sockaddr *)&serverStorage,&addr_size);
              printf("%s \n",buffer_control);
              for ( int i = 0 ; i <10*sizeof(int)/sizeof(int) ; i++){
                if(port_client_utilises[i] == 0 ){
                   port_client_utilises[i] = port+1+i; 
                   pid_process[i]= gestion_client ;
                   break ;               

                }
            }
          }
        }
    }
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


  close(server_desc_control);
  return 0;
  }
}
