COMPILER32      =g++
COMPILER64      =x86_64-w64-mingw32-g++
USE_COMPILER    =${COMPILER32}
COMPILER_FLAGS  =-O3 -std=c++20 -s -w -Wreturn-type ${MATH_EXTENSION} -Wno-attributes -Wno-enum-compare -Wno-write-strings -Wno-builtin-declaration-mismatch -fpermissive -fcheck-new -fno-exceptions -fno-rtti -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-math-errno -fno-unroll-loops -fmerge-all-constants -fno-ident -static
LINKER_FLAGS    =-s -lgcc -Wl,--exclude-all-symbols
OUTPUT_FLAGS    =-o $(OUTPUT_FILE)
OBJ_DIR         =obj/
OBJ_FILES       =$(wildcard $(OBJ_DIR)*.o)

# Add core and custom directories to compile list
CPP_FILES       +=$(wildcard ./*.cpp)
CPP_FILES       +=$(wildcard ../hde/*.cpp)

LINKER_FLAGS += -lWinmm

.PHONY: make_objects $(CPP_FILES)

make_objects: $(CPP_FILES)
$(CPP_FILES):
	@printf "[!] $(@F)\n"
	@$(eval count=$(shell echo $$(($(count)+1))))
	@$(USE_COMPILER) $@ -c -o $(OBJ_DIR)$(count).o $(COMPILER_FLAGS)
	
make_output: $(OBJ_FILES)
	@printf "[+] $(notdir $(OUTPUT_FILE))\n"
	@$(USE_COMPILER) $(OUTPUT_FLAGS) $(COMPILER_FLAGS) $^ $(LINKER_FLAGS)