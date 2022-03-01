#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <cassert>
#include <sys/mman.h>

class VM {
    private:
        std::map<unsigned, void(*)(VM*)> m_opcodes;
        std::vector<unsigned> m_callstack;

        unsigned m_opcode_size = 1;
        unsigned m_operand_size = 1;
        unsigned m_addr_size = 2;

        unsigned char m_regs[0x40] = {0};
        unsigned m_pc = 0;
        unsigned char *m_data;

        // Could inline this...
        unsigned r(unsigned num) {
            signed x = 0;
            for(int i = 0; i < num; i++) x |= (m_data[m_pc++]<<(8*i));
            return x;
        }

        signed rs(unsigned num) {
            signed x = 0;
            for(int i = 0; i < num; i++) x |= (m_data[m_pc++]<<(8*i));

            if(x & (1 << (8*num - 1))) {
                x |= 0xffffffff << (num*8);
            }
            return x;
        }
        
        friend void mov(VM*);
        friend void pr(VM*);
        friend void rd(VM*);
        friend void call(VM*);
        friend void ret(VM*);
        friend void ex(VM*);
        friend void remap(VM*);

        friend void f_add(VM*);
        friend void f_sub(VM*);
        friend void f_and(VM*);
        friend void f_xor(VM*);
        friend void f_shl(VM*);
        friend void f_shr(VM*);
        friend void f_not(VM*);

        friend void jmp(VM*);
        friend void jz(VM*);
        friend void store(VM*);
        friend void ld(VM*);
        friend void adr(VM*);
        friend void jl(VM*);

    public:
        VM(const char *path);
        void run();
};

void mov(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    unsigned op2 = vm->r(vm->m_operand_size);

    // src
    if(op2&0x80) op2 = vm->m_regs[op2-0x80];

    // dst 
    if(op1&0x80) vm->m_regs[op1-0x80] = op2;
    else assert(false && "non-register destination not implemented");
}
void f_add(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    unsigned op2 = vm->r(vm->m_operand_size);

    // src
    if(op2&0x80) op2 = vm->m_regs[op2-0x80];

    // dst 
    if(op1&0x80) vm->m_regs[op1-0x80] += op2;
    else assert(false && "non-register destination not implemented");
}
void f_sub(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    unsigned op2 = vm->r(vm->m_operand_size);

    // src
    if(op2&0x80) op2 = vm->m_regs[op2-0x80];

    // dst 
    if(op1&0x80) vm->m_regs[op1-0x80] -= op2;
    else assert(false && "non-register destination not implemented");
}

void f_and(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    unsigned op2 = vm->r(vm->m_operand_size);

    // src
    if(op2&0x80) op2 = vm->m_regs[op2-0x80];

    // dst 
    if(op1&0x80) vm->m_regs[op1-0x80] &= op2;
    else assert(false && "non-register destination not implemented");
}
void f_xor(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    unsigned op2 = vm->r(vm->m_operand_size);

    // src
    if(op2&0x80) op2 = vm->m_regs[op2-0x80];

    // dst 
    if(op1&0x80) vm->m_regs[op1-0x80] ^= op2;
    else assert(false && "non-register destination not implemented");
}
void f_shl(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    unsigned op2 = vm->r(vm->m_operand_size);

    // src
    if(op2&0x80) op2 = vm->m_regs[op2-0x80];

    // dst 
    if(op1&0x80) vm->m_regs[op1-0x80] <<= op2;
    else assert(false && "non-register destination not implemented");
}
void f_shr(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    unsigned op2 = vm->r(vm->m_operand_size);

    // src
    if(op2&0x80) op2 = vm->m_regs[op2-0x80];

    // dst 
    if(op1&0x80) vm->m_regs[op1-0x80] >>= op2;
    else assert(false && "non-register destination not implemented");
}

void pr(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    if(op1&0x80) op1 = vm->m_regs[op1-0x80];
    //std::cout << "[DBG] " << op1 << std::endl;
    std::cout << (char) op1;
}
void rd(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    if(op1&0x80) {
        //std::cout << "[*] Enter char: ";
        vm->m_regs[op1-0x80] = getc(stdin);
    }
}
void f_not(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    if(op1&0x80) {
        vm->m_regs[op1-0x80] = ~vm->m_regs[op1-0x80];
    }
}

void call(VM*vm) {
    int op1 = vm->rs(vm->m_addr_size);
    vm->m_callstack.push_back(vm->m_pc);

    if(op1>>8==0x69) {
        assert(false&&"call *x... not implemented"); 
    } else {
        vm->m_pc += op1;
    }
}
void jz(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    int dstz = vm->rs(vm->m_addr_size);
    if(op1&0x80) op1 = vm->m_regs[op1-0x80];
    if(!op1) {
        vm->m_pc += dstz;
    }
}
void jl(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    unsigned op2 = vm->r(vm->m_operand_size);
    int dstz = vm->rs(vm->m_addr_size);
    if(op1&0x80) op1 = vm->m_regs[op1-0x80];
    if(op2&0x80) op2 = vm->m_regs[op2-0x80];
    if(op1<op2) {
        vm->m_pc += dstz;
    }
}
void jmp(VM*vm) {
    int dstz = vm->rs(vm->m_addr_size);
    vm->m_pc += dstz;
}
void ret(VM*vm) {
    vm->m_pc = vm->m_callstack.back();
    vm->m_callstack.pop_back();
}
void ex(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    if(op1&0x80) op1 = vm->m_regs[op1-0x80];
    std::cout << "[-] Exit: " << op1 << std::endl;
    exit(op1);
}
void remap(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    unsigned op2 = vm->r(vm->m_operand_size);

    if(op1&0x80) op1 = vm->m_regs[op1-0x80];
    if(op2&0x80) op2 = vm->m_regs[op2-0x80];

    void (*tmp)(VM*vm) = vm->m_opcodes[op1];
    vm->m_opcodes[op1] = vm->m_opcodes[op2];
    vm->m_opcodes[op2] = tmp;
}
void store(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    int dstz = vm->rs(vm->m_addr_size);
    unsigned op2 = vm->r(vm->m_operand_size);
    if(op1&0x80) op1 = vm->m_regs[op1-0x80];
    if(op2&0x80) op2 = vm->m_regs[op2-0x80];
    //std::cout << "addr: " << vm->m_pc + dstz + op2 << ", "<< vm->m_pc + dstz << std::endl;
    vm->m_data[vm->m_pc + dstz + op2] = op1;
}
void ld(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    int dstz = vm->rs(vm->m_addr_size);
    unsigned op2 = vm->r(vm->m_operand_size);
    if(op2&0x80) op2 = vm->m_regs[op2-0x80];
    if(op1&0x80) {
        vm->m_regs[op1-0x80] = vm->m_data[vm->m_pc + dstz + op2];
    }
}
void adr(VM*vm) {
    unsigned op1 = vm->r(vm->m_operand_size);
    unsigned op2 = vm->r(vm->m_operand_size);
    int dstz = vm->rs(vm->m_addr_size);
    if((op1&0x80) && (op2&0x80)) {
        vm->m_regs[op2-0x80] = ((vm->m_pc + dstz)>>8)&0xff;
        vm->m_regs[op1-0x80] = (vm->m_pc + dstz)&0xff;
    }
}

VM::VM(const char *path) {
    std::ifstream file(path, std::ios_base::in | std::ios_base::binary);
    file.seekg(0, std::ios_base::end);
    size_t sz = file.tellg();
    file.seekg(0, std::ios_base::beg);

    
    m_data = (unsigned char*) mmap(nullptr, 0x11000 + ((sz+0xfff) / 0x1000) * 0x1000,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(m_data == (void*)-1) {
        std::cerr << "Error mmaping region!" << errno << std::endl;
        exit(0);
    }
    std::ifstream rnd("/dev/random");
    rnd.read((char*) &m_pc, 2);
    m_pc += 0x1000;

    file.read((char*) (m_data + m_pc), sz);
    //std::cout << "[DBG] Base offset: " << std::hex << m_pc << std::endl;

    m_opcodes[0] = mov;
    m_opcodes[1] = pr;
    m_opcodes[2] = call;
    m_opcodes[3] = ret;
    m_opcodes[4] = remap;

    m_opcodes[5] = f_add;
    m_opcodes[6] = f_and;
    m_opcodes[7] = f_xor;
    m_opcodes[8] = f_shl;
    m_opcodes[9] = f_shr;
    m_opcodes[10] = f_not;

    m_opcodes[11] = jz;
    m_opcodes[12] = jmp;

    m_opcodes[13] = f_sub;
    
    m_opcodes[14] = store;
    m_opcodes[15] = ld;
    m_opcodes[16] = adr;
    m_opcodes[17] = jl;
    m_opcodes[18] = rd;

    m_opcodes[0xff] = ex;
}

void VM::run() {
    while(1) {
        unsigned opcode = r(m_opcode_size);
        //std::cout << "[DBG] " << "executing: " << opcode << std::endl;
        if(!m_opcodes.contains(opcode)) {
            std::cerr << "Failure with opcode lookup! Failed opcode: " << opcode << std::endl;
            break;
        }
        (m_opcodes[opcode])(this);
    }
}

int main(int argc, char**args) {
    std::setbuf(stdin, nullptr);
    std::setbuf(stdout, nullptr);
    std::setbuf(stderr, nullptr);

    VM vm("out.bin");
    vm.run();
    return 0;
}

