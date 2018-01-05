CXX		= g++
CFLAGS  = -std=c++11 -Wno-attributes

Test_App_Name 			  ?= jalapeno_test 
Test_App_Cpp_Files 		:= $(Test_App_Name).cpp
Jalapeno_Lib_Path 		:= ../lib
Jalapeno_Lib 					:= $(Jalapeno_Lib_Path)/libjalapeno.so.1

#Test_App_Objects 		   := $(Test_App_Name).o
Test_App_Include_Flags := -I$(Jalapeno_Lib_Path)/App -I/opt/intel/sgxsdk/include -I$(Jalapeno_Lib_Path)
Test_App_Link_Flags 	 := -L$(Jalapeno_Lib_Path) -Wl,-rpath=$(Jalapeno_Lib_Path)

all: $(Test_App_Name)

#$(Test_App_Name): $(Test_App_Objects)
$(Test_App_Name): jalapeno_test.o
	$(CXX) $(CFLAGS) $^ -o $@ $(Jalapeno_Lib) $(Test_App_Link_Flags)

%.o: %.cpp
	$(CXX) $(CFLAGS) -c -o $@ $^ $(Test_App_Include_Flags)

.PHONY: clean

clean:
	rm -f *.o $(Test_App_Name)

#g++ -o jalapeno_test jalapeno_test.cpp /home/trippel/jalapeno/lib/libjalapeno.so.1 -L/home/trippel/jalapeno/lib -Wl,-rpath=/home/trippel/jalapeno/lib -I/home/trippel/jalapeno/lib/App -I/opt/intel/sgxsdk/include -I/home/trippel/jalapeno/lib
