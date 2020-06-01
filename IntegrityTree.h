//
// Created by root on 4/30/20.
//
#ifndef INTEGRITYTREE_INTEGRITYTREE_H
#define INTEGRITYTREE_INTEGRITYTREE_H

#include "openSSLWraps.h"
#include <queue>
#include <list>
#include <cassert>

#define BLOCK_SIZE 4096
#define NUM_OF_BLOCKS 8
#define HMAC_SIZE 16
#define NONCE_SIZE 12
#define BLOCK_MAX_ADDR 32767   // 1500 is in range for last block..
#define HMAC_MAX_ADDR 32895
#define SHA_LENGTH_BYTES 256 //probably 256 as sha256 says..
#define MEMORY_SIZE 32992
#define KEY_SIZE 16

typedef enum{
    INVALID_BLOCK_ADDR,
    INVALID_HMAC_ADDR,
    INVALID_NONCE_ADDR,
    TAMPERED_TREE,
    NO_RIGHT_NEIGHBOR,
    NO_LEFT_NEIGHBOR,
    INVALID_ADDR,
    SUCCESS
}ReturnValue;
void m_stdout(unsigned char* to_print,size_t num){
    for(int i=0;i<num;i++){
        std::cout<<to_print[i];
    }
}
unsigned char* m_strncpy(unsigned char* dest,unsigned char* src,size_t num){
    if(!dest || !src){
        return NULL;
    }
    for(int i=0;i<num;i++){
        dest[i]=src[i];
    }
    return dest;
}

unsigned char* m_strncat(unsigned char* dest,size_t index,unsigned char* src,size_t num){
    if(!dest || !src){
        return NULL;
    }
    int i = index;
    for(int j=0;j<num;j++){
        dest[i]=src[j];
        i++;
    }
    return dest;
}
int m_strncmp(unsigned char* str1,unsigned char* str2,size_t num){
    if(!str1 || !str2){
        return 5;
    }
    for(int i=0;i<num;i++){
        if(str1[i] != str2[i]){
            return str1[i]-str2[i];
        }
    }
    return 0;
}

void generate_random(unsigned char *s,int len) {
    static const char alphanum[] =
            "0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    //s[len] = 0;
}

class TrustedArea{
    std::vector<unsigned char*> trusted_memory;
    std::list<unsigned char*> tags_list; //FIFO (QUEUE)
    int index; //what's this for?
    int tag_counter;
public:
    TrustedArea():index(0), tag_counter(0){}
    ~TrustedArea(){
        if(index>0){
            for(int i=0;i<trusted_memory.size();i++){
                delete[] trusted_memory[i];
            }
        }
        if(tag_counter){
            auto it=tags_list.begin();
            for(int i=0;i<trusted_memory.size();i++){
                delete[] *it;
                it=tags_list.begin();
            }
            //FIXME: DELETE EVERY MEMBER OF LIST MANUALLY
            tags_list.clear();
            tag_counter = 0;
        }

    }
    unsigned char* allocate_in_trusted_memory(unsigned char* data,unsigned int len,bool isTag){
        unsigned char* mem_data=new unsigned char[len];
        m_strncpy(mem_data,data,len);
        if(!isTag) {
            trusted_memory.push_back((mem_data));
            ++index;
        }else{
            tags_list.push_back((mem_data));
            ++tag_counter;
        }
        return mem_data;
    }
    void deallocate_from_trusted_area(){
        delete[] (trusted_memory[index]);//to be checked..
        trusted_memory.pop_back();
        index--;
        return;
    }
    void delete_tag(){
        delete[] (tags_list.front());
        tags_list.pop_front();
        --tag_counter;
    }
    void update_root(unsigned char* new_root){
        delete[] (trusted_memory[0]);
        unsigned char* mem_root=new unsigned char[SHA_LENGTH_BYTES];
        m_strncpy(mem_root,new_root,SHA_LENGTH_BYTES);
        trusted_memory[0]=mem_root;
    }
    void update_key(int index_number,unsigned char* m_key){
        if(!index_number){
            return;
        }
        memset(trusted_memory[index_number],0,KEY_SIZE);
        m_strncpy(trusted_memory[index_number],m_key,KEY_SIZE);
    }
    void get_key(int index_number,unsigned char* buf){
        if(!index_number){
            return;
        }
        m_strncpy(buf,trusted_memory[index_number],KEY_SIZE);
    }
    unsigned char* get_tag(){
        return tags_list.front();
    }
    unsigned char* get_root(){
        return trusted_memory[0];
    }
    void print(){
        std::cout<<"TRUSTED MEMORY V20.4 \n\n\n\n";
        for(int i=0;i<trusted_memory.size();i++){
            std::cout<<"\n"<<trusted_memory[i]<<" \n ";
        }
        std::cout << "Tags\n\n";
        for(auto it = tags_list.begin(); it != tags_list.end(); ++it){
            std::cout << *it << std::endl;
        }
    }
    int get_number_of_tags(){
        return tags_list.size();
    }


};
TrustedArea trustedArea;
unsigned char memory[MEMORY_SIZE];
unsigned char blocks_data[BLOCK_SIZE*NUM_OF_BLOCKS];
void init_memory(){
    memset(blocks_data,0,sizeof(memory));
    int i;
    int data = 'A';
    for(i=0 ; i <= BLOCK_MAX_ADDR;i++){
        if(i % BLOCK_SIZE == 0 && i>0){
            data++;
        }
        blocks_data[i] = data;
    }
    //Allocating empty root, Will be updated later
    unsigned char root[12]="empty_root";
    trustedArea.allocate_in_trusted_memory(root,SHA_LENGTH_BYTES,false);
    for(i=0; i< NUM_OF_BLOCKS; i++){
        unsigned char* key=new unsigned char[KEY_SIZE];
        generate_random(key,KEY_SIZE);
        trustedArea.allocate_in_trusted_memory(key,KEY_SIZE,false);
        delete[] (key);
    }
    unsigned char nonce[NONCE_SIZE];
    int j=0;
    generate_random(nonce,NONCE_SIZE);
    for(i=HMAC_MAX_ADDR + 1 ; i < MEMORY_SIZE;i++){
        if(i % HMAC_SIZE == 0){
            j=0;
            generate_random(nonce,NONCE_SIZE);
        }
        memory[i] = nonce[j++];
    }
    //return memory;
}


void encrypt_memory(){
    int j=0;

    int k=HMAC_MAX_ADDR + 1;
    int mem_index=0;
    unsigned char ciphertext[BLOCK_SIZE];
    unsigned char tag[16];
    unsigned char aad[256]="";
    for(int i=0;i<NUM_OF_BLOCKS;i++){
        memset(ciphertext,0,BLOCK_SIZE);
        memset(tag,0,HMAC_SIZE);
        unsigned char* plaintext=new unsigned char[BLOCK_SIZE];
        m_strncpy(plaintext,(blocks_data + i*BLOCK_SIZE),BLOCK_SIZE);
        unsigned char* key=new unsigned char[KEY_SIZE];
        trustedArea.get_key(i+1,key);
        unsigned char* nonce=new unsigned char[NONCE_SIZE];
        m_strncpy(nonce,(memory + (k + (i*NONCE_SIZE))),NONCE_SIZE);
//        std::cout<<"Plain Text: "<<plaintext<<std::endl;
//        std::cout<<"Key: "<<key<<std::endl;
//        std::cout<<"NONCE: "<<nonce<<std::endl;
        int cipher_len=gcm_encrypt(plaintext,BLOCK_SIZE,aad,256,key,nonce,NONCE_SIZE,ciphertext,tag);
        m_strncpy((memory+i*BLOCK_SIZE),ciphertext,BLOCK_SIZE);
        m_strncpy((memory+ BLOCK_MAX_ADDR+1 + i*HMAC_SIZE),tag,HMAC_SIZE);
        delete[] plaintext;
        delete[] nonce;
        delete[] key;
    }
}
void update_memory(int addr,char value){
    memory[addr]=value;
}
void print_trusted_memory() {
    trustedArea.print();
}
void print_memory(){
    int i;
//    std::cout<< " MEMORY (NON-VOLATILE)\n"<<memory;
    for( i = 0; i < MEMORY_SIZE; i++){
        std::cout<< " " << memory[i] << " ";
    }
}
void print_blocks_data(){
    int i;
    for( i = 0; i < BLOCK_SIZE*NUM_OF_BLOCKS; i++){
        std::cout<< " " << blocks_data[i] << " ";
    }
    std::cout<<std::endl;
}
ReturnValue memwrite(uint64_t addr,unsigned char* buf,int size){
    if(addr < 0 || addr > MEMORY_SIZE){
        return INVALID_ADDR;
    }
    int i,j=0;
    for(i = (int)addr; i < addr + size ; i++){
        memory[i]=buf[j++];
    }
    return SUCCESS;
}
ReturnValue memread(uint64_t addr,unsigned char* buf,int size){
    //char* tmp;
    if(addr < 0 || addr > MEMORY_SIZE){
        return INVALID_ADDR;
    }
    int i,j=0;
    for(i = (int)addr; i < addr + size ; i++){
        buf[j++]=memory[i];
    }
    return SUCCESS;
}

//64 bit address
int block_id(uint64_t addr){
    if(addr<0 || addr>BLOCK_MAX_ADDR){
        return INVALID_BLOCK_ADDR;
    }
    return (int)((addr)/((uint64_t)(BLOCK_SIZE)));
}
int hmac_id(uint64_t addr){
    if(addr<=BLOCK_MAX_ADDR || addr>HMAC_MAX_ADDR){
        return INVALID_HMAC_ADDR;
    }
    uint64_t offset = addr - BLOCK_MAX_ADDR;
    return (int)((offset)/((uint64_t)(HMAC_SIZE)));
}
// Input: Block address
// Output: HMAC address of the same block...
uint64_t hmac_addr(uint64_t addr){
    if(addr<0 || addr>BLOCK_MAX_ADDR){
        return INVALID_BLOCK_ADDR;
    }
    uint64_t _block_id=block_id(addr);
    return NUM_OF_BLOCKS*BLOCK_SIZE + _block_id * HMAC_SIZE;
}
uint64_t nonce_addr(uint64_t addr){
    if(addr<0 || addr>BLOCK_MAX_ADDR){
        return INVALID_BLOCK_ADDR;
    }
    uint64_t _block_id=block_id(addr);
    return NUM_OF_BLOCKS*BLOCK_SIZE + NUM_OF_BLOCKS * HMAC_SIZE + _block_id * NONCE_SIZE;
}




ReturnValue getRoot(unsigned char* result){
    int j=1;
    for(int i = BLOCK_MAX_ADDR + 1; i<= HMAC_MAX_ADDR-2*HMAC_SIZE+1; i+= 2*HMAC_SIZE) {
        unsigned char buf1[HMAC_SIZE], buf2[HMAC_SIZE];
        memset(buf1,0,HMAC_SIZE);
        memset(buf2,0,HMAC_SIZE);
        memread(i, buf1, HMAC_SIZE);
        memread(i + HMAC_SIZE, buf2, HMAC_SIZE);
        unsigned char tmp[2 * HMAC_SIZE];
        memset(tmp,0,2*HMAC_SIZE);
        m_strncpy(tmp,buf1, HMAC_SIZE);
        m_strncat(tmp,HMAC_SIZE,buf2, HMAC_SIZE);
        unsigned char hashed_data[SHA_LENGTH_BYTES];
        memset(hashed_data,0,SHA_LENGTH_BYTES);
        SHA256(tmp,sizeof(tmp), hashed_data);
        trustedArea.allocate_in_trusted_memory(hashed_data,sizeof(hashed_data),true);

    }
   // std::cout << trustedArea.get_number_of_tags();
    int n=0; //Que eso?
    while((n=trustedArea.get_number_of_tags())>1){
        for(int i=0; i<= n-2; i+=2){
            unsigned char sha2[2*SHA_LENGTH_BYTES];
            memset(sha2,0,2*SHA_LENGTH_BYTES);
            m_strncpy(sha2, trustedArea.get_tag(),SHA_LENGTH_BYTES);
            trustedArea.delete_tag();
            m_strncat(sha2,SHA_LENGTH_BYTES,trustedArea.get_tag(),SHA_LENGTH_BYTES);
            trustedArea.delete_tag();
            unsigned char hashed_data[SHA_LENGTH_BYTES];
            memset(hashed_data,0,SHA_LENGTH_BYTES);
            SHA256(sha2,sizeof(sha2), hashed_data);
            trustedArea.allocate_in_trusted_memory(hashed_data,sizeof(hashed_data),true);
        }
    }

  //  std::cout<<"\nTHE ROOTT ISSSS : \n\n\n\n";
  //  std::cout<<trustedArea.get_tag();

    m_strncpy(result,trustedArea.get_tag(),SHA_LENGTH_BYTES);
    trustedArea.delete_tag();

    return SUCCESS;

}



bool verify_integrity(){
    unsigned char curr_root[SHA_LENGTH_BYTES];
    memset(curr_root,0,SHA_LENGTH_BYTES);
    getRoot(curr_root);
    if(!m_strncmp(curr_root,(trustedArea.get_root()),SHA_LENGTH_BYTES)){
//        std::cout<<"\n\nTHE TREE IS VALID---\n";
        return true;
    }
    std::cout<<"THE TREE IS FUCKED:( LEAVE AND THROW THE PC NOWWWW!\n\n\n\n";
    return false;
}

int read_block(uint64_t addr,unsigned char* buf){
    int index = block_id(addr);
    if(!verify_integrity()){
        return 0;
    }
    unsigned char tmp_buf[BLOCK_SIZE];
    memread(index*BLOCK_SIZE,tmp_buf,BLOCK_SIZE);
    uint64_t nonce_address=nonce_addr(addr);
    uint64_t hmac_address=hmac_addr(addr);
    unsigned char nonce[NONCE_SIZE];
    unsigned char hmac[HMAC_SIZE];
    unsigned char* key=new unsigned char[KEY_SIZE];
    trustedArea.get_key(index+1,key);  //Found key
    memread(nonce_address,nonce,NONCE_SIZE);          // Found nonce value
    memread(hmac_address,hmac,HMAC_SIZE);             // Found Hmac value
    unsigned char aad[256]="";

    int read_size = gcm_decrypt(tmp_buf,BLOCK_SIZE,aad,256,hmac,key,nonce,NONCE_SIZE,buf);
    delete[] key;
    return read_size;                          // How many bytes we actually decrypted and read
}
int write_block(uint64_t addr,unsigned char* buf,int size_to_write){
    int index = block_id(addr);
    if(!verify_integrity()){
        return -1;                  //ERROR
    }
    unsigned char block_data[BLOCK_SIZE];
    uint64_t nonce_address=nonce_addr(addr);
    uint64_t hmac_address=hmac_addr(addr);
    read_block(addr,block_data);
    int j=addr - (index*BLOCK_SIZE);
    for(int i=0; i < size_to_write ;i++){
        block_data[j++]=buf[i];
    }
    unsigned char ciphertext[BLOCK_SIZE];
    unsigned char new_tag[16];
    unsigned char new_aad[256]="";
    unsigned char* new_key=new unsigned char[KEY_SIZE];
    trustedArea.get_key(index+1,new_key);  //Found key
    unsigned char* new_nonce=new unsigned char[NONCE_SIZE];
    memset(ciphertext,0,BLOCK_SIZE);
    memset(new_tag,0,HMAC_SIZE);
    memset(new_key,0,KEY_SIZE);
    generate_random(new_nonce,NONCE_SIZE);
    generate_random(new_key,KEY_SIZE);
    std::cout<<"the old key is: \n";
    m_stdout(new_key,KEY_SIZE);
    gcm_encrypt(block_data,BLOCK_SIZE,new_aad,256,new_key,new_nonce,NONCE_SIZE,ciphertext,new_tag);
    // Update Ciphertext,HMAC, NONCE
    memwrite(index*BLOCK_SIZE,ciphertext,BLOCK_SIZE);
    memwrite(hmac_address,new_tag,HMAC_SIZE);
    memwrite(nonce_address,new_nonce,NONCE_SIZE);



    // Now update Trusted area key...
    trustedArea.update_key(index+1,new_key);


    //TODO RED
    unsigned char adham[BLOCK_SIZE];
    unsigned char tmp_buf[BLOCK_SIZE];
    memread(index*BLOCK_SIZE,tmp_buf,BLOCK_SIZE);
    unsigned char nonce[NONCE_SIZE];
    unsigned char hmac[HMAC_SIZE];
    unsigned char* test_key=new unsigned char[KEY_SIZE];
    trustedArea.get_key(index+1,test_key);  //Found key
    std::cout<<"\n Key after shit:\n";
    m_stdout(test_key,KEY_SIZE);
    memread(nonce_address,nonce,NONCE_SIZE);          // Found nonce value
    memread(hmac_address,hmac,HMAC_SIZE);             // Found Hmac value
    unsigned char aad[256]="";



    std::cout<<"\nThe diff between ciphers is: "<<m_strncmp(tmp_buf,ciphertext,BLOCK_SIZE)<<std::endl;
    std::cout<<"The diff between tags is: "<<m_strncmp(hmac,new_tag,HMAC_SIZE)<<std::endl;
    std::cout<<"The diff between keys is: "<<m_strncmp(test_key,new_key,KEY_SIZE)<<std::endl;
    std::cout<<"The diff between NONCES is: "<<m_strncmp(nonce,new_nonce,NONCE_SIZE)<<std::endl;


    int read_size = gcm_decrypt(tmp_buf,BLOCK_SIZE,aad,256,hmac,test_key,nonce,NONCE_SIZE,adham);

    m_stdout(adham,BLOCK_SIZE);
    unsigned char new_root[SHA_LENGTH_BYTES];
    getRoot(new_root);
    trustedArea.update_root(new_root);
    delete[] new_key;
    delete[] test_key;
    delete[] new_nonce;
    return 0;
}

#endif //INTEGRITYTREE_INTEGRITYTREE_H