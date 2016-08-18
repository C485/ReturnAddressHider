ReturnAddressHider
--------
Simple header only library to chenge return address on current stack frame.
Features
--------
* Supports x86 and x64 code
* Easy to use

TO DO
--------
* Add tests
* Add ability to change return addresses in all frames.
* Add Linux support

Requirements
-----
* C++14
* Windows XP or later
* 32/64 bit application
* Only x86-32/x86-64

Example
-----
    #include "CallHider.h"
    #include <iostream>
    
    void* RandomPlaceInSecuredFunctionDll = nullptr;
    
    static __declspec(noinline) int SecuredFunction()
    {
    	//you can call this function only from RandomPlaceInSecuredFunctionDll!
    	//Normally this will be in protected DLL/EXE
    	auto isInRange = [&](void* start, void* end, void* ptr) {
    		return (uint64_t)start <= (uint64_t)ptr && (uint64_t)ptr <= (uint64_t)end;
    	};
    	if (isInRange(RandomPlaceInSecuredFunctionDll, (char*)RandomPlaceInSecuredFunctionDll + 500, _ReturnAddress()))
    	{
    		return 0;
    	}
    	return 88;
    }
    
    int main() {
    	{
    		//Be sure that these two functions are not inline!
    		ReturnAddressHider tmp;
    		RandomPlaceInSecuredFunctionDll = VirtualAlloc(NULL, 500, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    		FlushInstructionCache(GetCurrentProcess(), NULL, NULL);
    		try
    		{
    			if (SecuredFunction() == 88)
    				std::cout << "Normal call!!";
    			else
    				std::cout << "Call from RandomPlaceInSecuredFunctionDll!!!";
    			auto addr1 = RandomPlaceInSecuredFunctionDll;
    			auto addr2 = (void*)&SecuredFunction;
    			tmp.Process(addr1, addr2);
    			int(*func)(void) = (int(*)(void))RandomPlaceInSecuredFunctionDll;
    			getchar();
    			if (func() == 88)
    				std::cout << "Normal call!!";
    			else
    				std::cout << "Call from RandomPlaceInSecuredFunctionDll!!!";
    		}
    		catch (std::exception e)
    		{
    			std::cout << e.what();
    		}
    		catch (...)
    		{
    			std::cout << "?";
    		}
    		VirtualFree(RandomPlaceInSecuredFunctionDll, 0, MEM_RELEASE);
    	}
    
    	return 0;
    }
<center>
![enter image description here](https://i.imgur.com/znfnPFm.png)
</center>
License
-------
See LICENSE file for details.
