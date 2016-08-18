#include "ReturnAddressHider.h"
#include <iostream>

void* RandomPlaceInSecuredFunctionDll = nullptr;

static __declspec(noinline) void SecuredFunction()
{
	//you can call this function only from RandomPlaceInSecuredFunctionDll!
	//Normally this will be in protected DLL/EXE
	auto isInRange = [&](void* start, void* end, void* ptr) {
		return (uint64_t)start <= (uint64_t)ptr && (uint64_t)ptr <= (uint64_t)end;
	};
#ifdef _MSC_VER
	if (isInRange(RandomPlaceInSecuredFunctionDll, (char*)RandomPlaceInSecuredFunctionDll + 500, _ReturnAddress()))
#else
	if (isInRange(RandomPlaceInSecuredFunctionDll, (char*)RandomPlaceInSecuredFunctionDll + 500, __builtin_return_address(0)))
#endif

		std::cout << "Access granted!\n";
	else
		std::cout << "Access denied!\n";
}

static __declspec(noinline) void test() {
	ReturnAddressHider tmp;
	try {
		//Lets call function from main ( this will fail )
		SecuredFunction();

		//Now lets call same function from another place in memory
		//This will succeed
		auto addr1 = RandomPlaceInSecuredFunctionDll;
		auto addr2 = (void*)&SecuredFunction;
		//Be sure that these two functions are not inline!
		tmp.Process(addr1, addr2);
		//Now RandomPlaceInSecuredFunctionDll contains a forwarder to SecuredFunction
		void(*func)(void) = (void(*)(void))RandomPlaceInSecuredFunctionDll;
		func();
	}
	catch (std::exception e) {
		std::cout << e.what();
	}
	catch (...) {
		std::cout << "?";
	}
}

int main() {
	RandomPlaceInSecuredFunctionDll = VirtualAlloc(NULL, 500, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	FlushInstructionCache(GetCurrentProcess(), nullptr, (SIZE_T)0);
	test();
	VirtualFree(RandomPlaceInSecuredFunctionDll, 0, MEM_RELEASE);
	return 0;
}