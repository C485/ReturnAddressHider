//
// Copyright(c) 2016 C485.
// Distributed under the MIT License (http://opensource.org/licenses/MIT)
//

#pragma once
#include <Windows.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <memory>
#include <tuple>

enum class _ReturnAddressHiderType : uint8_t {
	_64Bit64BitAddress,
	_32Bit32BitAddress
};

class ReturnAddressHider {
public:
	ReturnAddressHider(bool = true);
	ReturnAddressHider(ReturnAddressHider&&) = default;
	ReturnAddressHider& operator = (ReturnAddressHider&&) = default;
	ReturnAddressHider(const ReturnAddressHider&) = delete;
	ReturnAddressHider& operator = (const ReturnAddressHider&) = delete;
	virtual ~ReturnAddressHider();
public:
	void Process(const void *, const void *);
	void SetMode(_ReturnAddressHiderType = (sizeof(void*) == 4) ? (_ReturnAddressHiderType::_32Bit32BitAddress) : (_ReturnAddressHiderType::_64Bit64BitAddress));
private:
	void genAsm(const void *, const void *);
	void RestoreCode();
	void Clear();

	template <typename A>
	using checkIntegralType = typename std::enable_if<std::is_integral<A>::value, A>::type;

	template <typename A, typename B>
	using checkIsSameType = typename std::enable_if<std::is_same<A, B>::value, A>::type;

	template <typename A>
	using checkIsPointerType = typename std::enable_if<std::is_pointer<A>::value, A>::type;

	template <typename A, typename B, checkIsSameType<A, B> = 0>
	bool EqualToOneOf(const A &a, const B &b) {
		return a == b;
	}

	template <typename A, typename B, typename... C> bool EqualToOneOf(const A &a, const B &b, C const &... args) {
		return a == b || EqualToOneOf(a, args...);
	}

	template <typename A, checkIntegralType<A> = 0>
	std::string IntegralToHexString(const A val) {
		char buff[100] = { 0 };
		sprintf_s(buff, "%llx", (uint64_t)val);
		return buff;
	}

	template <typename A, checkIsPointerType<A> = 0>
	std::string IntegralToHexString(const A val) {
		char buff[100] = { 0 };
		sprintf_s(buff, "%llx", (uint64_t)val);
		return buff;
	}

	template <typename A, checkIntegralType<A> = 0>
	void AppendInt(const A val) {
		for (int i = 0; i < sizeof(A) * 8; i += 8)
			mGeneratedAsmCode.push_back((uint8_t)((val >> i) & 0xff));
	}

	inline void AppendCode(const std::initializer_list<uint8_t> &p) {
		for (auto i : p)
			mGeneratedAsmCode.push_back(i);
	}

	template <typename A, checkIntegralType<A> = 0>
	void AppendCodeAndNumber(const std::initializer_list<uint8_t> &p, const A val) {
		AppendCode(p);
		AppendInt(val);
	}

	template <typename C, typename A, typename B, checkIsPointerType<A> = 0, checkIntegralType<B> = 0>
	void AppendCodePointerWithOffset(const std::initializer_list<uint8_t> &p, const A val, const B offset) {
		AppendCode(p);
		// to get rid off 'type cast' : pointer truncation from ...
		// why there is no option to tell compiler that i know what i doing :/
		union {
			C val2 = 0;
			void* val;
		} junk;
		junk.val = (void*)val;
		AppendInt(junk.val2 + offset);
	}

	inline uint32_t PtrTouint32_t(const void *p) {
		return((uint32_t)(UINT_PTR)p);
	}
private:
	std::unique_ptr<uint8_t[]> mRestoreOryginalCodeData;
	bool mRestorCode;
	std::vector<uint8_t> mGeneratedAsmCode;
	std::tuple<const void*, const void*, uint32_t> mRestoreDataInfo;
	_ReturnAddressHiderType mMode;
};

inline ReturnAddressHider::ReturnAddressHider(bool _RestoreCode) : mRestorCode(_RestoreCode) {
	mGeneratedAsmCode.reserve(100);
	SetMode();
}

inline ReturnAddressHider::~ReturnAddressHider() {
	RestoreCode();
}

inline void ReturnAddressHider::Process(const void *_CallFromAddress, const void *_TrueFunctionAddress) {
	MEMORY_BASIC_INFORMATION _CallFromAddressMemInfo, _TrueFunctionAddressMemInfo;
	uint64_t _llCallFromAddress = (uint64_t)_CallFromAddress, _llTrueFunctionAddress = (uint64_t)_TrueFunctionAddress;
	DWORD _junk, _junk2;

	auto getMaxRegionAddress = [](const MEMORY_BASIC_INFORMATION& mem) -> uint64_t {
		return (uint64_t)mem.BaseAddress + mem.RegionSize;
	};

	auto isInsideMemoryBlock = [&getMaxRegionAddress](const MEMORY_BASIC_INFORMATION& mem, uint64_t addr) {
		return (uint64_t)mem.BaseAddress <= addr && addr <= getMaxRegionAddress(mem);
	};

	if (VirtualQuery(_CallFromAddress, &_CallFromAddressMemInfo, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
		throw std::runtime_error(std::string("Failed to VirtualQuery[") + IntegralToHexString(_llCallFromAddress) + "] with GetLastError[" + IntegralToHexString(GetLastError()) + "]\n");
	if (VirtualQuery(_TrueFunctionAddress, &_TrueFunctionAddressMemInfo, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
		throw std::runtime_error(std::string("Failed to VirtualQuery[") + IntegralToHexString(_llTrueFunctionAddress) + "] with GetLastError[" + IntegralToHexString(GetLastError()) + "]\n");
	if (!isInsideMemoryBlock(_CallFromAddressMemInfo, _llCallFromAddress))
		throw std::runtime_error(IntegralToHexString(_llCallFromAddress) + " is not valid address!!\n");
	if (!isInsideMemoryBlock(_TrueFunctionAddressMemInfo, _llTrueFunctionAddress))
		throw std::runtime_error(IntegralToHexString(_llTrueFunctionAddress) + " is not valid address!!\n");
	if (!EqualToOneOf((int)_TrueFunctionAddressMemInfo.Protect, PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE))
		throw std::runtime_error(IntegralToHexString(_llCallFromAddress) + " is not executable!!\n");
	if (_CallFromAddressMemInfo.State != MEM_COMMIT)
		throw std::runtime_error(IntegralToHexString(_llCallFromAddress) + " is not in committed page!!\n");
	if (VirtualProtect(_CallFromAddressMemInfo.BaseAddress, _CallFromAddressMemInfo.RegionSize, PAGE_EXECUTE_READWRITE, &_junk) == 0)
		throw std::runtime_error(std::string("Failed to VirtualProtect[") + IntegralToHexString(_CallFromAddressMemInfo.BaseAddress) + "] with GetLastError[" + IntegralToHexString(GetLastError()) + "]\n");
	genAsm(_CallFromAddress, _TrueFunctionAddress);
	auto isTherePlaceForAsmCode = [&]() -> bool {
		auto sizeOfStruct = (uint64_t)mGeneratedAsmCode.size();
		auto restPageSize = getMaxRegionAddress(_CallFromAddressMemInfo) - _llCallFromAddress;
		return restPageSize > sizeOfStruct;
	};
	if (!isTherePlaceForAsmCode()) {
		VirtualProtect(_CallFromAddressMemInfo.BaseAddress, _CallFromAddressMemInfo.RegionSize, _junk, &_junk2);
		throw std::runtime_error("Not enough space for Assembly code, region protection restored!!\n");
	}
	if (mRestorCode) {
		mRestoreOryginalCodeData = std::make_unique<uint8_t[]>(mGeneratedAsmCode.size());
		memcpy(mRestoreOryginalCodeData.get(), _CallFromAddress, mGeneratedAsmCode.size());
	}
	memcpy((void*)_CallFromAddress, &mGeneratedAsmCode[0], mGeneratedAsmCode.size());
	mRestoreDataInfo = std::make_tuple(_CallFromAddress, (const void*)_CallFromAddressMemInfo.BaseAddress, (uint32_t)_CallFromAddressMemInfo.RegionSize);
	if (FlushInstructionCache(GetCurrentProcess(), NULL, NULL) == NULL)
	{
		auto err = GetLastError();
		VirtualProtect(_CallFromAddressMemInfo.BaseAddress, _CallFromAddressMemInfo.RegionSize, _junk, &_junk2);
		throw std::runtime_error(std::string("Failed to FlushInstructionCache with GetLastError[") + IntegralToHexString(err) + "], region protection restored!!\n");
	}
}

inline void ReturnAddressHider::SetMode(_ReturnAddressHiderType _mode) {
	mMode = _mode;
}

inline void ReturnAddressHider::genAsm(const void *_CallFromAddress, const void *_TrueFunctionAddress) {
	RestoreCode();
	if (mMode == _ReturnAddressHiderType::_32Bit32BitAddress) {
		AppendCode({ 0x50 });																	//50					- push eax
		AppendCode({ 0x8B, 0x44, 0x24, 0x04 });													//8B 44 24 04           - mov eax,[esp+04]
		AppendCodePointerWithOffset<uint32_t>({ 0x89, 0x05 }, _CallFromAddress, 27);			//89 05 66666666        - mov [66666666],eax
		AppendCodePointerWithOffset<uint32_t>({ 0xC7, 0x44, 0x24, 0x04 }, _CallFromAddress, 26);//C7 44 24 04 66666666  - mov [esp+04],66666666
		AppendCode({ 0x58 });																	//58                    - pop eax
		AppendCodePointerWithOffset<uint32_t>({ 0x68 }, _TrueFunctionAddress, 0);				//68 CCCCCCCC           - push CCCCCCCC
		AppendCode({ 0xC3 });																	//C3					- ret
		AppendCodeAndNumber({ 0x68 }, (uint32_t)0);												//68 CCCCCCCC			- push CCCCCCCC
		AppendCode({ 0xC3 });																	//C3					- ret
	}
	else if (mMode == _ReturnAddressHiderType::_64Bit64BitAddress) {
		AppendCode({ 0x50 });																	//50					- push rax
		AppendCode({ 0x53 });																	//53					- push rbx
		AppendCode({ 0x48, 0x8B, 0x44, 0x24, 0x10 });											//48 8B 44 24 10		- mov rax, [rsp + 10]
		AppendCodePointerWithOffset<uint64_t>({ 0x48, 0xBB }, _CallFromAddress, 51);			//48 BB int				- mov rbx, int
		AppendCode({ 0x48, 0x89, 0x03 });														//48 89 03				- mov[rbx], rax
		AppendCode({ 0x48, 0x83, 0xEB, 0x06 });													//48 83 EB 06			- sub rbx,06 { 6 }
		AppendCode({ 0x48, 0x89, 0x5C, 0x24, 0x10 });											//48 89 5C 24 10		- mov [rsp+10],rbx
		AppendCode({ 0x5B });																	//5B					- pop rbx
		AppendCode({ 0x58 });																	//58					- pop rax
		AppendCodePointerWithOffset<uint64_t>({ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 },
			_TrueFunctionAddress, 0);															//FF 25 00000000		- jmp qword ptr[int]
		AppendCodeAndNumber({ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }, (uint64_t)0);				//FF 25 00000000		- jmp qword ptr[int]
	}
	else
		throw std::runtime_error("u wot m8? xD");
}

inline void ReturnAddressHider::RestoreCode() {
	try {
		if (mRestorCode && std::get<0>(mRestoreDataInfo) && mRestoreOryginalCodeData) {
			DWORD _junk, _junk2;
			if (VirtualProtect((void*)std::get<1>(mRestoreDataInfo), std::get<2>(mRestoreDataInfo), PAGE_EXECUTE_READWRITE, &_junk) == 0)
				throw std::runtime_error(std::string("Failed to VirtualProtect[") + IntegralToHexString(std::get<1>(mRestoreDataInfo)) + "] with GetLastError[" + IntegralToHexString(GetLastError()) + "]\n");
			memcpy((void*)std::get<0>(mRestoreDataInfo), mRestoreOryginalCodeData.get(), mGeneratedAsmCode.size());
			if (VirtualProtect((void*)std::get<1>(mRestoreDataInfo), std::get<2>(mRestoreDataInfo), _junk, &_junk2) == 0)
				throw std::runtime_error(std::string("Failed to VirtualProtect[") + IntegralToHexString(std::get<1>(mRestoreDataInfo)) + "] with GetLastError[" + IntegralToHexString(GetLastError()) + "]\n");
			if (FlushInstructionCache(GetCurrentProcess(), NULL, NULL) == NULL)
				throw std::runtime_error(std::string("Failed to FlushInstructionCache with GetLastError[") + IntegralToHexString(GetLastError()) + "]\n");
		}
	}
	catch (...) {
		Clear();
		throw;
	}
}

inline void ReturnAddressHider::Clear() {
	std::get<0>(mRestoreDataInfo) = nullptr;
	std::get<1>(mRestoreDataInfo) = nullptr;
	std::get<2>(mRestoreDataInfo) = 0;
	mRestoreOryginalCodeData.reset(nullptr);
	mGeneratedAsmCode.clear();
}