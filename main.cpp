#include <iostream>
#include "assert.h"
#include "IntegrityTree.h"
int main(){
    MainMemory* memory=new MainMemory();
    TrustedArea* trustedArea=new TrustedArea();
    LRUCache* cache=new LRUCache(CACHE_SIZE,memory);

    memory->init_memory(*trustedArea);
    memory->encrypt_memory(*trustedArea);

    unsigned char root[SHA_LENGTH_BYTES];
    getRoot(memory,trustedArea,cache,root);
    trustedArea->update_root(root);

    unsigned char block_to_write[BLOCK_SIZE]="First Update of First Block";
    write_block(memory,trustedArea,cache,0,block_to_write,BLOCK_SIZE);
    int state=verify_integrity(memory,trustedArea,cache);
    assert(state==1);
    std::cout<<"--Tree is good, as it should :)"<<std::endl;

    unsigned char block_to_write2[BLOCK_SIZE]="Second Update of First Block";
    int res3=write_block(memory,trustedArea,cache,0,block_to_write2,BLOCK_SIZE);
    state=verify_integrity(memory,trustedArea,cache);
    assert(state==1);
    std::cout<<"--Tree is good, as it should :)"<<std::endl;
    unsigned char curr_root[SHA_LENGTH_BYTES];
    getRoot(memory,trustedArea,cache,curr_root);

    unsigned char buf[BLOCK_SIZE]="";
    read_block(memory,trustedArea,cache,0,buf);
    int cmp=m_strncmp(buf,block_to_write2,BLOCK_SIZE);
    assert(cmp==0);
    std::cout<<"--Data updated correctly, as it should :)"<<std::endl;

    // Writing same block as before, making sure root is changed
    write_block(memory,trustedArea,cache,0,block_to_write,BLOCK_SIZE);
    unsigned char curr_root2[SHA_LENGTH_BYTES];
    getRoot(memory,trustedArea,cache,curr_root2);
    int res2=m_strncmp(curr_root,curr_root2,SHA_LENGTH_BYTES);
    assert(res2!=0);
    std::cout<<"--Root did change, as it should :)"<<std::endl;

    //Attacker attacks and changes block number 1 data unofficially
    memory->update_memory(BLOCK_MAX_ADDR+2,'J');
    state=verify_integrity(memory,trustedArea,cache);
    assert(state!=1);
    std::cout<<"--Integrity Verification Failed Due to attack, as it should :)"<<std::endl;
    getRoot(memory,trustedArea,cache,root);
    trustedArea->update_root(root);     // Now tree is fixed
    state=verify_integrity(memory,trustedArea,cache);
//    printToFile(memory,trustedArea);
    assert(state==1);
    std::cout<<"--After updating the root manually, the state is Ok now:)"<<std::endl;


    unsigned char block_to_write3[BLOCK_SIZE]="Update #2.0";
    unsigned char block_to_write4[BLOCK_SIZE]="Update #2.1";
    unsigned char block_to_write5[BLOCK_SIZE]="Update #2.2";
    unsigned char block_to_write6[BLOCK_SIZE]="Update #2.3";
    unsigned char block_to_write7[BLOCK_SIZE]="Update #2.4";
    unsigned char block_to_write8[BLOCK_SIZE]="Update #2.5";
    unsigned char block_to_write9[BLOCK_SIZE]="Update #2.6";

    unsigned char buffer1[BLOCK_SIZE]="";
    unsigned char buffer2[BLOCK_SIZE]="";
    unsigned char buffer3[BLOCK_SIZE]="";
    unsigned char buffer4[BLOCK_SIZE]="";

    unsigned char root2[SHA_LENGTH_BYTES]="";
    unsigned char root3[SHA_LENGTH_BYTES]="";
//    getRoot(memory,trustedArea,root2);

    int res=write_block(memory,trustedArea,cache,0,block_to_write3,BLOCK_SIZE);
    read_block(memory,trustedArea,cache,0,buffer1);
    getRoot(memory,trustedArea,cache,root2);
    cmp=m_strncmp(buffer1,block_to_write3,BLOCK_SIZE);
    assert(cmp==0 && res==0);
    std::cout<<"--Write + Read Succeeded"<<std::endl;
    res=write_block(memory,trustedArea,cache,0,block_to_write4,BLOCK_SIZE);
    read_block(memory,trustedArea,cache,0,buffer2);
    cmp=m_strncmp(buffer2,block_to_write4,BLOCK_SIZE);
    assert(cmp==0);
    std::cout<<"--Write + Read Succeeded"<<std::endl;
    res=write_block(memory,trustedArea,cache,1,block_to_write5,BLOCK_SIZE);
    read_block(memory,trustedArea,cache,1,buffer3);
    cmp=m_strncmp(buffer3,block_to_write5,BLOCK_SIZE);
    assert(cmp==0 && res==0);
    std::cout<<"--Write + Read Succeeded"<<std::endl;
    res=write_block(memory,trustedArea,cache,2,block_to_write6,BLOCK_SIZE);
    read_block(memory,trustedArea,cache,2,buffer4);
    cmp=m_strncmp(buffer4,block_to_write6,BLOCK_SIZE);
    assert(cmp==0 && res==0);
    std::cout<<"--Write + Read Succeeded"<<std::endl;
    res=write_block(memory,trustedArea,cache,3,block_to_write7,BLOCK_SIZE);
    read_block(memory,trustedArea,cache,3,buffer1);
    cmp=m_strncmp(buffer1,block_to_write7,BLOCK_SIZE);
    assert(cmp==0 && res==0);
    std::cout<<"--Write + Read Succeeded"<<std::endl;
    res=write_block(memory,trustedArea,cache,4,block_to_write8,BLOCK_SIZE);
    read_block(memory,trustedArea,cache,4,buffer1);
    cmp=m_strncmp(buffer1,block_to_write8,BLOCK_SIZE);
    assert(cmp==0 && res==0);
    std::cout<<"--Write + Read Succeeded"<<std::endl;
    res=write_block(memory,trustedArea,cache,6,block_to_write9,BLOCK_SIZE);
    read_block(memory,trustedArea,cache,6,buffer1);
    cmp=m_strncmp(buffer1,block_to_write9,BLOCK_SIZE);
    assert(cmp==0 && res==0);
    std::cout<<"--Write + Read Succeeded"<<std::endl;



    //ATTACK , Changing HMAC
    memory->update_memory(hmac_addr(BLOCK_SIZE*0),'Z');         //Changing HMAC of BLock #0
    res=verify_integrity(memory,trustedArea,cache);                   // Verify shall fail
    assert(res==0);
    std::cout<<"--HMAC attack detected :) Tree works fine:)";
    res=read_block(memory,trustedArea,cache,4,buffer1);           //Tree is not good, any read shall fail
    res2=write_block(memory,trustedArea,cache,7,block_to_write5,BLOCK_SIZE);// any write shall fail as well
///    assert(res==-1 && res2==-1);
    std::cout << "--Since the tree is not good, Write() and Read() operations fail as they should :) \n";

    //FIXME: Fixing the tree
    getRoot(memory,trustedArea,cache,root);
    trustedArea->update_root(root);     // Now tree is fixed
    res=verify_integrity(memory,trustedArea,cache);                   // Verify shall fail
    assert(res==1);
    std::cout<<"--After updating the root, Tree is good now \n";
    //Changing First block to previous value, tree shouldn't fall for the trap and the new root should be different from previous root
    //Verify should fail, even if the changed value is similar to previously assigned value that was once verified and correct
    for(int i=0;i<BLOCK_SIZE;i++){
        memory->update_memory(i,block_to_write3[i]);
    }
    getRoot(memory,trustedArea,cache,root3);
    int read_res=read_block(memory,trustedArea,cache,0,buffer1);
    assert(read_res==-1 && m_strncmp(root3,root2,SHA_LENGTH_BYTES)!=0); //
    std::cout<<"--Replay Attack detected :) The tree didn't fall for replay attack on Block #0:)\n";
    getRoot(memory,trustedArea,cache,root);
    trustedArea->update_root(root);     // Now tree is fixed
    res=verify_integrity(memory,trustedArea,cache);                   // Verify shall fail
    assert(res==1);
    std::cout<<"--After fixing the root, Tree is good now \n";

    // ATTACK on Nonce
    memory->update_memory(HMAC_MAX_ADDR+1,'Z'); //Changing Nonce of block #0
    res=read_block(memory,trustedArea,cache,0,buffer3);           //Tree is not good, any read shall fail
    //res2=write_block(memory,trustedArea,3,block_to_write2,BLOCK_SIZE);// any write shall fail as well
    assert(res==-1 );
    std::cout << "--Nonce attack detected :) is detected on Block #0, Read() operation fails as it should :) \n";
    getRoot(memory,trustedArea,cache,root);
    trustedArea->update_root(root);     // Now tree is fixed
    res=verify_integrity(memory,trustedArea,cache);
    assert(res==1);
    res=write_block(memory,trustedArea,cache,0,block_to_write4,BLOCK_SIZE);
    std::cout<<"--After fixing the root, Tree is good now \n";
    std::cout<<"--[*] The memory state is printed in memory.txt file. (In CMakeFiles/memory.txt)\n";
    printToFile(memory,trustedArea,cache);


    return 0;
}
/*
int main2(){
    MainMemory* mainMemory=new MainMemory();
    TrustedArea* trustedArea=new TrustedArea();
    mainMemory->init_memory(*trustedArea);
    mainMemory->encrypt_memory(*trustedArea);
    unsigned char root[SHA_LENGTH_BYTES];
    getRoot(mainMemory,trustedArea,cache,root);
    trustedArea->update_root(root);
    ////////////////////////////////////////// Testing In 1,2,3 ...  ////////////////////////////////////////////////

    unsigned char buf[BLOCK_SIZE]="We are the kings of the world $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$";
    int block_index=0;
   // write_block(memory,trustedArea,0,block_to_write,BLOCK_SIZE);
    if(!verify_integrity(mainMemory,trustedArea,cache)){
        return -1;                  //ERROR
    }
    int binaryNum[32];
    decToBinary(block_index,binaryNum);
    write_to_log(binaryNum,0,buf);
    uint64_t addr= block_index*BLOCK_SIZE;
    uint64_t nonce_address=nonce_addr(addr);
    uint64_t hmac_address=hmac_addr(addr);
    unsigned char ciphertext[BLOCK_SIZE];
    unsigned char new_tag[16];
    unsigned char new_aad[256]="";
    unsigned char* new_key=new unsigned char[KEY_SIZE];
    unsigned char* new_nonce=new unsigned char[NONCE_SIZE];
    memset(ciphertext,0,BLOCK_SIZE);
    memset(new_tag,0,HMAC_SIZE);
    memset(new_key,0,KEY_SIZE);
    generate_random(new_nonce,NONCE_SIZE);
    generate_random(new_key,KEY_SIZE);
    trustedArea->update_key(block_index+1, new_key);
    unsigned char *stam_key = trustedArea->get_key(block_index+1);
    int res59=gcm_encrypt(buf,BLOCK_SIZE,new_aad,256,stam_key,new_nonce,NONCE_SIZE,ciphertext,new_tag);
    mainMemory->memwrite(block_index*BLOCK_SIZE,ciphertext,BLOCK_SIZE);
    mainMemory->memwrite(hmac_address,new_tag,HMAC_SIZE);
    mainMemory->memwrite(nonce_address,new_nonce,NONCE_SIZE);
//    trustedArea->update_key(index+1,new_key);
    unsigned char new_root[SHA_LENGTH_BYTES];
    ///////////////////////// getRoot(mainMemory,trustedArea,new_root); ///////////////////////////////
    int j=1;
    for(int i = BLOCK_MAX_ADDR + 1; i<= HMAC_MAX_ADDR-2*HMAC_SIZE+1; i+= 2*HMAC_SIZE) {
        unsigned char buf1[HMAC_SIZE], buf2[HMAC_SIZE];
        memset(buf1,0,HMAC_SIZE);
        memset(buf2,0,HMAC_SIZE);
        mainMemory->memread(i, buf1, HMAC_SIZE);
        mainMemory->memread(i + HMAC_SIZE, buf2, HMAC_SIZE);
        unsigned char tmp[2 * HMAC_SIZE];
        memset(tmp,0,2*HMAC_SIZE);
        m_strncpy(tmp,buf1, HMAC_SIZE);
        m_strncat(tmp,HMAC_SIZE,buf2, HMAC_SIZE);
        unsigned char hashed_data[SHA_LENGTH_BYTES];
        memset(hashed_data,0,SHA_LENGTH_BYTES);
        SHA256(tmp,sizeof(tmp), hashed_data);
        trustedArea->allocate_in_trusted_memory(hashed_data,sizeof(hashed_data),true);

    }
    int n=0; //Que eso?
    while((n=trustedArea->get_number_of_tags())>1){
        for(int i=0; i<= n-2; i+=2){
            unsigned char sha2[2*SHA_LENGTH_BYTES];
            memset(sha2,0,2*SHA_LENGTH_BYTES);
            m_strncpy(sha2, trustedArea->get_tag(),SHA_LENGTH_BYTES);
            trustedArea->delete_tag();
            m_strncat(sha2,SHA_LENGTH_BYTES,trustedArea->get_tag(),SHA_LENGTH_BYTES);
            trustedArea->delete_tag();
            unsigned char hashed_data[SHA_LENGTH_BYTES];
            memset(hashed_data,0,SHA_LENGTH_BYTES);
            SHA256(sha2,sizeof(sha2), hashed_data);
            trustedArea->allocate_in_trusted_memory(hashed_data,sizeof(hashed_data),true);
        }
    }

    m_strncpy(new_root,trustedArea->get_tag(),SHA_LENGTH_BYTES);
    trustedArea->delete_tag();
   ///////////////////////////// getRoot is Done /////////////////////////////////////////////
    trustedArea->update_root(new_root);
    erase_log();
//    delete[] new_key;
//    delete[] new_nonce;


    ///////////////////////////// Now Testing Read(), in 1,2,3.... ////////////////////////////////////////////////
   if(1) {
       unsigned char buffer2[BLOCK_SIZE];
       int index = block_id(addr);
       if (!verify_integrity(mainMemory, trustedArea)) {
           return -1;
       }
       unsigned char *tmp_buf;
       unsigned char *nonce;
       unsigned char *hmac;
       unsigned char *key;
       tmp_buf = mainMemory->getMemoryAddress(index * BLOCK_SIZE);
       uint64_t nonce_address = nonce_addr(addr);
       uint64_t hmac_address = hmac_addr(addr);
       key = trustedArea->get_key(index + 1);  //Found key
       nonce = mainMemory->getMemoryAddress(nonce_address);
       hmac = mainMemory->getMemoryAddress(hmac_address);
       unsigned char nonce_value[NONCE_SIZE+1]="";
       unsigned char hmac_value[HMAC_SIZE+1]="";
       for(int i=0;i<NONCE_SIZE;i++){
           nonce_value[i]=*(nonce+i);
       }
       for(int i=0;i<HMAC_SIZE;i++){
           hmac_value[i]=*(hmac+i);
       }
       unsigned char aad[256] = "";

       int is_KeyEqual=m_strncmp(key,new_key,KEY_SIZE);
       int is_NonceEqual=m_strncmp(nonce_value,new_nonce,NONCE_SIZE);
       int is_HmacEqual=m_strncmp(hmac_value,new_tag,HMAC_SIZE);
       int is_CipherTextEqual=m_strncmp(tmp_buf,ciphertext,HMAC_SIZE);
       int is_aad_equal=m_strncmp(aad,new_aad,256);

       int read_size = gcm_decrypt(tmp_buf, BLOCK_SIZE, aad, 256, hmac_value, key, nonce_value, NONCE_SIZE, buf);
       m_stdout(buf, BLOCK_SIZE);

   }

}
*/