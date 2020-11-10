import sys
block_size=sys.argv[1]
num_of_blocks=sys.argv[2]
iterations=sys.argv[3];
original_stdout = sys.stdout
from random import choice
import string
curr_index=0;
def GenContent(length=8, chars=string.letters + string.digits):
    return ''.join([choice(chars) for i in range(length)])
def write_to_block(index,block_to_write):
    print('write_block(memory,trustedArea,cache,'+index+','+block_to_write+',BLOCK_SIZE);')
def read_block(index,buf_name):
    print('read_block(memory,trustedArea,cache,'+index+','+buf_name+');')
def verify_integrity():
    print('state=verify_integrity(memory,trustedArea,cache);')
    print('assert(state==1);')
def check_content(var1,var2):
    print('cmp=m_strncmp('+var1+','+var2+',BLOCK_SIZE);')
    print('assert(cmp==0);')
def set_block_to_write(new_content):
    print('unsigned char block_to_write'+str(curr_index)+'[BLOCK_SIZE]="'+str(new_content)+'";')
#    print('memset(block_to_write'+str(curr_index)+',0,BLOCK_SIZE);')
    #print(varname+'='+'"'+new_content+'"'+';')
def print_in_c(text):
    print('std::cout<<"'+text+'"<<std::endl;');
with open('test.txt','w') as f:
	sys.stdout = f;
	#print('#include <iostream>\n#include "MainMemory.h"\n#include "IntegrityTree.h"\n#include "assert.h"\n')
	print('int main(){')
	print('MainMemory* memory=new MainMemory(); \n \
	    TrustedArea* trustedArea=new TrustedArea(); \n\
	    LRUCache* cache=new LRUCache(CACHE_SIZE,memory->getMemoryPointer());\n\
	    memory->init_memory(trustedArea);\n\
	    memory->encrypt_memory(trustedArea);\n\
	    unsigned char root[SHA_LENGTH_BYTES];\n\
	    getRoot(memory,trustedArea,cache,root);\n\
	    trustedArea->update_root(root);	\n\
	    unsigned char block_to_write[BLOCK_SIZE];\n\
    	    unsigned char block_read[BLOCK_SIZE];\n\
    	    auto start=std::chrono::high_resolution_clock::now();\n\
    	    auto finish=std::chrono::high_resolution_clock::now();\n\
    	    std::chrono::duration<double> elapsed; \n\
	    std::vector<double> write_times;\n\
	    std::vector<double> read_times;\n\
    	    int cmp=0;\n\
	    int state=0;\n')
	#print('-------------------------')
	lst=[];
	for i in range(int(iterations)):
		#print('std::cout<<"-------Iteration #'+str(i+1)+'---------------------------------------------------------------------------------"<<std::endl;')
		for j in range(int(num_of_blocks)):
			randContent=GenContent(int(block_size),string.letters)
			set_block_to_write(randContent);
			print('start = std::chrono::high_resolution_clock::now();');
			write_to_block(str(j),'block_to_write'+str(curr_index));
			print('finish = std::chrono::high_resolution_clock::now();');
			print('elapsed = finish - start;');
			print('write_times.push_back(elapsed.count());');
			#print('std::cout<<"Elapsed time for write_block is:" << elapsed.count() << std::endl;');
			
			print('start = std::chrono::high_resolution_clock::now();');
			read_block(str(j),'block_read');
			print('finish = std::chrono::high_resolution_clock::now();');
			print('elapsed = finish - start;');
			print('read_times.push_back(elapsed.count());');
			#print('std::cout<<"Elapsed time for read_block is:" << elapsed.count() << std::endl;');
			
			check_content('block_to_write'+str(curr_index),'block_read');
			verify_integrity();
			#print('std::cout<<"Write+Read+Verify performed successfully to Block'+str(j)+'"'+'<<std::endl'+';');
			curr_index=curr_index+1;
			#print('-------------------------');
			#print_in_c('********');
	
	print('std::sort(write_times.begin(),write_times.end());');
	print('std::sort(read_times.begin(),read_times.end());');
	print('double write_median=write_times[write_times.size() / 2];');
	print('double read_median=read_times[read_times.size() / 2];');
	print('std::cout<<"The median of read is: "<<read_median<<std::endl;');
	print('std::cout<<"The median of write is: "<<write_median<<std::endl;');
	print('}')	
	sys.stdout = original_stdout
