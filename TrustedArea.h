//
// Created by root on 6/6/20.
//
#ifndef INTEGRITYTREE_TRUSTEDAREA_H
#define INTEGRITYTREE_TRUSTEDAREA_H
#include "m_stdio.h"
#include <cstring>
#include <vector>
#include <list>
#include <unordered_map>
#include <assert.h>
#define SHA_LENGTH_BYTES 256 //probably 256 as sha256 says..
#define KEY_SIZE 32
#define CACHE_ENTRIES ((6400) / HMAC_SIZE)
#define HMAC_SIZE 16

class CacheKey {
public:
    int height, index;
    CacheKey(int height, int index):height(height), index(index){}
    CacheKey (const CacheKey &other){
        height = other.height;
        index = other.index;
    }
    bool operator==(const CacheKey &other) const{
        return height == other.height && index == other.index;
    }
    friend std::ostream& operator<<(std::ostream& os, const CacheKey &c_key);
};

std::ostream& operator<<(std::ostream& os, const CacheKey &c_key){
    os << c_key.height << " " << c_key.index;
    return os;
}
namespace std {
    template<>
    struct hash<CacheKey> {
        std::size_t operator()(const CacheKey &k) const {
            using std::size_t;
            using std::hash;
            using std::string;

            // Compute individual hash values for first,
            // second and third and combine them using XOR
            // and bit shifting:

            return ((hash<int>()(k.height)
                     ^ (hash<int>()(k.index) << 1)) << 1);
        }
    };
}

class LRUCache {
    //MainMemory* mainMemory;
    unsigned char *memory;
    // store keys of cac    he
    std::list<unsigned char *> dq;
    // store references of key in cache
    std::unordered_map<CacheKey, typename std::list<unsigned char *>::iterator> ma;
//    std::vector<unsigned char*> allocs;
    //unsigned char* pointers;
    int csize; // maximum capacity of cache
    int hit_counter=0;

public:
    // Declare the size
    LRUCache(int n, unsigned char *mainMemory1) {
        csize = n;
        memory = mainMemory1;
//        pointers=new unsigned char[15*HMAC_SIZE];
    }

    // Refers key x with in the LRU cache
    void refer(int height, int index, unsigned char* buf){
        // not present in cache
        CacheKey cache_key = CacheKey(height,index);
        if (ma.find(cache_key) == ma.end()) {
            // cache is full
            if (dq.size() == csize) {
                unsigned char *last = dq.back();// delete least recently used element
                auto it = ma.begin();
                for(; it!=ma.end(); ++it){
                    if(!strncmp((char*)*it->second, (char *)last, HMAC_SIZE))
                        break;
                }
                if(it!=ma.end())
                    ma.erase(it);
                dq.pop_back();                 // Pops the last element
                unsigned char* list_buf=new unsigned char[HMAC_SIZE];
//                allocs.push_back(list_buf);
                m_strncpy(list_buf,buf,HMAC_SIZE);
                dq.push_front(list_buf);
                ma[cache_key] = dq.begin();
//                delete[] list_buf;
                return;
            }
            unsigned char* list_buf=new unsigned char[HMAC_SIZE];
//            allocs.push_back(list_buf);
            m_strncpy(list_buf,buf,HMAC_SIZE);
            dq.push_front(list_buf); // Cache is not full, but there is a MISS
            ma[cache_key] = dq.begin();
//            delete[] list_buf;
            return;
        }
            // present in cache
        else {
          //  std::cout<< "Cache Hit\n";
            hit_counter++;
            unsigned char* list_buf2 = new unsigned char[HMAC_SIZE];
//            allocs.push_back(buf);
            memset(list_buf2, 0, HMAC_SIZE);
            m_strncpy(list_buf2, buf, HMAC_SIZE);
            //FIXME: Deleting current node from memory

            dq.erase(ma[cache_key]);
            dq.push_front(list_buf2);
            ma[cache_key] = dq.begin();
//            delete[] buf;
        }

    }
    unsigned char* read_from_cache(int height, int index) {
        CacheKey cache_key = CacheKey(height, index);
        if (ma.find(cache_key) == ma.end()) {
            return NULL;
        }
      //  std::cout<< "Cache Hit from read\n";
        unsigned char* res= ma[cache_key].operator*();
        refer(height, index, res);
        return res;
    }
    unsigned char* is_in_cache(int height, int index){
        if(height > TREE_HEIGHT){
            return NULL;
        }
        CacheKey cache_key = CacheKey(height,index);
        if (ma.find(cache_key) == ma.end()) {
            return NULL;
        }
//        std::cout<< "Cache Hit from read\n";
        hit_counter++;
        unsigned char* res= ma[cache_key].operator*();
        return res;
    }
    void update_cache(int height, int index,unsigned char* new_hmac_data){
        CacheKey cache_key = CacheKey(height,index);
        if (ma.find(cache_key) == ma.end()) {
            return;
        }
        unsigned char* pointer = ma[cache_key].operator*();
        memset(pointer, 0, HMAC_SIZE);
        m_strncpy(pointer,new_hmac_data, HMAC_SIZE);
    }

    void write_to_cache(int height, int index, unsigned char *value) {
        CacheKey cache_key = CacheKey(height,index);
        refer(height,index,value);
        unsigned char *pointer = ma[cache_key].operator*();
        memset(pointer, 0, HMAC_SIZE);
        m_strncpy(pointer,value, HMAC_SIZE);
    }

    void display() { // Function to display contents of cache

        // Iterate in the deque and print
        // all the elements in it
        for (auto it = dq.begin(); it != dq.end();
             it++)
            std::cout << (*it) << " ";

        std::cout << std::endl;
    }
    void displayMap(){
        for (auto it = ma.begin(); it != ma.end();it++)
            std::cout << (it).operator*().first << " " << *(it).operator*().second << std::endl;

    }
    void print_map(){
        for (auto const& pair: ma) {
            std::cout << "{" << pair.first << ": " << *pair.second << "}\n";
        }
    }

    //INPUT: index of node in tree
    //OUTPUT: index of right son index in tree
    CacheKey getRightSon(int height, int index) {
        if(height==TREE_HEIGHT){
            return CacheKey(height,index);
        }
        return CacheKey(height+1, 2*index+1);
    }

    CacheKey getLeftSon(int height, int index) {
        if(height==TREE_HEIGHT){
            return CacheKey(height,index);
        }
        return CacheKey(height+1, 2*index);
    }

    CacheKey getParentIndex(int height, int index) {
        return CacheKey(height-1, index/2);
    }
    CacheKey getBrother(int height,int index){
        CacheKey parent=getParentIndex(height,index);
        CacheKey rson = getRightSon(parent.height,parent.index);
        CacheKey lson = getLeftSon(parent.height,parent.index);
        if(height==rson.height && index==rson.index){
            return lson;
        }
        return rson;
    }
    int getSide(int height,int index){  // 0 Left 1 Right
        CacheKey parent=getParentIndex(height,index);
        CacheKey rson = getRightSon(parent.height,parent.index);
        CacheKey lson = getLeftSon(parent.height,parent.index);
        if(height==rson.height && index==rson.index){
            return 1;
        }
        return 0;
    }
//    int* getMapping(int node_index) {
//        return (int*)(pointers) + node_index * (HMAC_SIZE);
//    }
    //HON LSHO'3OL YA 3ZEZE
//    unsigned char* getDataPointer(MainMemory* mainMemory,CacheKey node){
//        unsigned char* buf = is_in_cache(node.height,node.index);
//        if(node.height == TREE_HEIGHT || buf!=NULL){
//            if(!buf){
//                 mainMemory->memread(,);
//            }
//            return buf;
//        }
//        return nullptr;
//    }

//    //INPUT: address of certain node in tree
//    //OUTPUT: index of that node. (Node 0, Node 1/Node 5 ....)
//    int reverseMapping(unsigned char *node_address) {
//        return ( node_address - pointers) / HMAC_SIZE;
//    }
    int get_hit_counter(){
        return hit_counter;
    }
    void flush(){
        int i=0;
        int size=ma.size();
        for(i=0;i<size;i++){
            ma.erase(ma.begin());
        }
        int size2=dq.size();
        for(i=0;i<size2;i++){
            dq.erase(dq.begin());
        }
//        int len=allocs.size();
//        for(i=size-1;i>=0;i--){
//            delete[] allocs[i];
//            //allocs.pop_back();
//        }
//        allocs.clear();
//        delete[] pointers;

//        pointers=new unsigned char[15*HMAC_SIZE];
        assert(dq.size()==0 && ma.size()==0);
    }
//    void fillPointersArray(int block_index, unsigned char* data){
//        unsigned char* hmac_=getDataPointer(block_index);
//        for(int i=0;i<HMAC_SIZE;i++){
//            hmac_[i]=data[i];
//        }
//    }
    ~LRUCache(){
        flush();
    }
};



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
    unsigned char* get_key(int index_number){
        if(!index_number){
            return NULL;
        }
        //m_strncpy(buf,trusted_memory[index_number],KEY_SIZE);
        return trusted_memory[index_number];
    }
    unsigned char* get_tag(){
        return tags_list.front();
    }
    unsigned char* get_root(){
        return trusted_memory[0];
    }
    void print(){
//        std::cout<<"TRUSTED MEMORY V20.4 \n\n\n\n";
//        for(int i=0;i<trusted_memory.size();i++){
//            std::cout<<"\n"<<trusted_memory[i]<<" \n ";
//        }
        std::cout << "Tags\n\n";
        for(auto it = tags_list.begin(); it != tags_list.end(); ++it){
            std::cout << it.operator*() << std::endl;
        }
    }
    int get_number_of_tags(){
        return tags_list.size();
    }


};


#endif