CXX		= g++
CFLAGS  = -std=c++11 -Wno-attributes

Test_App_Name 			  ?= commpact_test 
Test_App_Cpp_Files 		:= $(Test_App_Name).cpp
CommPact_Lib_Path 		:= ../lib
CommPact_Lib 					:= $(CommPact_Lib_Path)/libcommpact.so.1

#Test_App_Objects 		   := $(Test_App_Name).o
Test_App_Include_Flags := -I$(CommPact_Lib_Path)/App -I/opt/intel/sgxsdk/include -I$(CommPact_Lib_Path)
Test_App_Link_Flags 	 := -L$(CommPact_Lib_Path) -Wl,-rpath=$(CommPact_Lib_Path)

all: $(Test_App_Name)

#$(Test_App_Name): $(Test_App_Objects)
$(Test_App_Name): commpact_test.o
	$(CXX) $(CFLAGS) $^ -o $@ $(CommPact_Lib) $(Test_App_Link_Flags)

%.o: %.cpp
	$(CXX) $(CFLAGS) -c -o $@ $^ $(Test_App_Include_Flags)

.PHONY: clean

clean:
	rm -f *.o $(Test_App_Name)

