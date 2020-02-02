typedef struct _INOUT_PARAM{
	ULONG Param1;
	ULONG Param2;
	ULONG Param3;
	ULONG Param4;
} INOUT_PARAM, *PINOUT_PARAM;

#define DUMMYDRV_REQUEST1    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

VOID test(
	VOID
	)
{
	HANDLE          h;
	INOUT_PARAM     tmp;
	DWORD           bytesIO;

	h = CreateFile(TEXT("\\\\.\\TDLD"), GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (h != INVALID_HANDLE_VALUE) {

		tmp.Param1 = 0xAAAAAAAA;
		tmp.Param2 = 0xBBBBBBBB;
		tmp.Param3 = 0xCCCCCCCC;
		tmp.Param4 = 0xDDDDDDDD;

		DeviceIoControl(h, DUMMYDRV_REQUEST1,
			&tmp, sizeof(tmp), &tmp,
			sizeof(tmp), &bytesIO, NULL);

		CloseHandle(h);
	}

}