#include <stdio.h>
#include <atlstr.h> //用于CString
#include <vector>
#include <windows.h>
#include <Tlhelp32.h>
#pragma warning(disable : 4996) //用于屏蔽strcyp等不安全函数错误
using std::vector;

//#include <iostream>  //用于控制台打印正常
//#include <shlobj_core.h>

//DWORD dwSize=0;
//char* pBuf = NULL;
//BOOL loadFile(WCHAR* Arr_PeFilePath) {
//	HANDLE hFile = CreateFileW(Arr_PeFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//	
//	if (hFile==INVALID_HANDLE_VALUE)
//	{
//		printf("读取%S失败\n", Arr_PeFilePath);
//		Sleep(3000);
//		delete[]Arr_PeFilePath;
//		return 1;
//	}
//	
//	dwSize = GetFileSize(hFile, 0);
//	pBuf = new char[dwSize];
//	DWORD dwRealSize = 0;
//	ReadFile(hFile, pBuf, dwSize, &dwRealSize, NULL);
//	CloseHandle(hFile);
//	return 0;
//}


//通过创建进程演示获取文件路径
//void GetFilePathCreateProcess() {
//
//	HWND hConsoleWnd = FindWindowW(L"ConsoleWindowClass", NULL);
//	WCHAR FilePathName[MAX_PATH * 2]{};
//
//	//获取文件路径名
//	OPENFILENAMEW file = { 0 };
//	file.hwndOwner = hConsoleWnd;
//	file.lStructSize = sizeof(file);
//	file.lpstrFilter = L"所有文件(*.*)\0*.*\0Exe文件(*.exe)\0*.exe\0\0";//要选择的文件后缀 
//	file.lpstrInitialDir = L"";//默认的文件路径 
//	file.lpstrFile = FilePathName;//存放文件名称的缓冲区 
//	file.nMaxFile = _countof(FilePathName);
//	file.nFilterIndex = 0;
//	file.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;//标志如果是多选要加上OFN_ALLOWMULTISELECT
//	BOOL bSel = GetOpenFileNameW(&file);
//	CString filePath = file.lpstrFile;
//
//	STARTUPINFO si{};         //启动信息结构体
//	PROCESS_INFORMATION pi{}; //进程信息结构体
//	si.cb = sizeof(STARTUPINFO);  //初始化启动信息结构体大小
//	BOOL Ret = CreateProcess(filePath.GetBuffer(), NULL,
//		NULL, NULL,
//		FALSE,
//		CREATE_NEW_CONSOLE, NULL, NULL,
//		&si, &pi);
//	if (!Ret)
//	{
//		printf("Error on CreateProcess");
//		return;
//	}
//}

//遍历exe  
//void FilePathCollection(const WCHAR* BasePath, vector<WCHAR*>& vec_FilePath) {
//
//	//获取给定文件夹中所有文件路径信息
//	WIN32_FIND_DATAW  wfd = {};
//	setlocale(LC_ALL, "CHS"); // 设置字符编码格式
//	WCHAR szDirtoryPath[MAX_PATH * 2] = { 0 };
//	swprintf_s(szDirtoryPath, MAX_PATH * 2, L"%s\\%s", BasePath, L"*");
//	HANDLE hFindFile = FindFirstFileW(szDirtoryPath, &wfd);
//	if (hFindFile != INVALID_HANDLE_VALUE) {
//		do {
//
//			if ((wcscmp(wfd.cFileName, L".")) != 0 && (wcscmp(wfd.cFileName, L"..")) != 0)
//			{
//				if ((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
//				{
//					CStringW temp;
//					temp.Format(L"%s\\%s", BasePath, wfd.cFileName);
//					FilePathCollection(temp, vec_FilePath);
//				}
//
//				else
//				{
//					//挑选dll文件放入
//					BOOL flag = 0;
//					int LenFilename = wcslen(wfd.cFileName);
//					for (int i = 0; i < LenFilename; i++)
//					{
//						if (_wcsicmp((wfd.cFileName + i), L".exe") == 0)
//						{
//							flag = 1;
//							break;
//						}
//					}
//
//					//保存到vector中
//					if (flag)
//					{
//						CStringW temp;
//						temp.Format(L"%s\\%s", BasePath, wfd.cFileName);
//						WCHAR* pTemp = new WCHAR[wcslen(temp.GetBuffer()) + 1];
//						wcscpy_s(pTemp, wcslen(temp.GetBuffer()) + 1, temp.GetBuffer());
//						//vec_FilePath.push_back(pTemp);
//
//						//读取被感染exe到内存
//						BOOL Ret=loadFile(pTemp);
//
//						if (Ret)
//						{
//							continue;
//						}
//						//倒数读取被感染程序的文件大小的ASCII码
//						//转化成数字
//
//
//						//方便点直接复制到结尾
//
//						//定位到0x18200h处，循环写入到新文件 wfd.cFileName
//						DWORD loc[2] = { 0x18200,0x7531 };
//						for (size_t i = 0; i < 2; i++)
//						{
//							char* pOriginExe = pBuf + loc[i];
//							int OriginSize = dwSize - loc[i];
//							if (OriginSize > 0)
//							{
//								if (*pOriginExe == 'M' && *(pOriginExe + 1) == 'Z')
//								{
//
//									char FileName[MAX_PATH];
//									size_t RetNum = 0;
//									wcstombs_s(&RetNum, FileName, MAX_PATH, pTemp, MAX_PATH);
//
//									FILE* pExeFile = NULL;
//									errno_t ret = fopen_s(&pExeFile, FileName, "wb+");
//									if (ret)
//									{
//										return;
//									}
//									fwrite(pOriginExe, 1, OriginSize, pExeFile);
//
//									printf("%S已经修复\n", pTemp);
//								}
//
//
//							}
//						}
//						
//						delete[]pTemp;
//						delete[]pBuf;
//					}
//				}
//			}
//		} while (FindNextFileW(hFindFile, &wfd));
//	}
//
//}

//---------------------------------------------------


// 全局变量用于统计
int FixBinaryFileNumber = 0;
int FixScriptFileNumber = 0;
int DelDesktop_iniFileNumber = 0;
int SizeOfVirusFile_Bytes = 0;
char path[MAX_PATH];														// 保存病毒文件路径

// 结束指定进程，参数为目标进程字符串
BOOL KillPandaProcess(const char* pszProcessName)
{
	BOOL bKill = FALSE;
	HANDLE hProcess;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)									// 如果获取进程快照失败，返回 FALSE
	{
		return bKill;
	}
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);
	BOOL bRet = Process32First(hProcessSnap, &pe);								// 获取第一个进程
	while (bRet)
	{
		if (strcmp(pe.szExeFile, pszProcessName) == 0)
		{
			bKill = TRUE;
			hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
			int ret = TerminateProcess(hProcess, 1);							// 终止进程
			if (ret)
			{
				printf("Yeah!Panda's Process is dead!\n\n");
			}
			else
			{
				printf("OMG!Panda is still alive!\n\n");
			}
			break;
		}
		bRet = Process32Next(hProcessSnap, &pe);
	}
	CloseHandle(hProcessSnap);
	return bKill;
}

// 修复注册表
void FixReg()
{
	// 删除svcshare
	char RegRun[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	HKEY hKeyHKCU = NULL;
	LONG lSize = MAXBYTE;
	char cData[MAXBYTE] = { 0 };
	long lRet = RegOpenKey(HKEY_CURRENT_USER, RegRun, &hKeyHKCU);
	if (lRet == ERROR_SUCCESS)
	{
		lRet = RegQueryValueEx(hKeyHKCU, "svcshare", NULL, NULL, (unsigned char*)cData, (unsigned long*)&lSize);
		if (lRet == ERROR_SUCCESS)
		{
			if (strcmp(cData, "C:\\WINDOWS\\system32\\drivers\\spo0lsv.exe") == 0)
			{
				printf("Find virus AutorunRegInfo!\n\n");
			}
			lRet = RegDeleteValue(hKeyHKCU, "svcshare");
			if (lRet == ERROR_SUCCESS)
			{
				printf("Panda's RegItem has beed deleted!\n\n");
			}
			else
			{
				printf("Panda's RegItem is still alive or is gone!\n\n");
			}
		}
		else
		{
			printf("Reg is clear!\n\n");
		}
		RegCloseKey(hKeyHKCU);
	}
	else
	{
		printf("Open Reg failed!\n\n");
	}
	// 修复文件的隐藏显示，将CheckedValue的值设置为1
	char RegHide[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL";
	HKEY hKeyHKLM = NULL;
	DWORD dwFlag = 1;
	long lRetHide = RegOpenKey(HKEY_LOCAL_MACHINE, RegHide, &hKeyHKLM);
	if (lRetHide == ERROR_SUCCESS)
	{
		if (ERROR_SUCCESS == RegSetValueEx(
			hKeyHKLM,             //subkey handle  
			"CheckedValue",       //value name  
			0,                    //must be zero  
			REG_DWORD,            //value type  
			(CONST BYTE*) & dwFlag, //pointer to value data  
			4))                   //length of value data
		{
			printf("Reg fixed!\n\n");
		}
		else
		{
			printf("Can't fix RegHiddenItem or it's clear!\n\n");
		}
	}

}

// 删除指定文件
BOOL DelSPecificFile(const char* FileName)
{
	// 去除文件的隐藏、系统以及只读属性
	DWORD dwFileAttributes = GetFileAttributes(FileName);						// 获取文件属性
	dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;									// &=~ 是去掉属性，| 是增加属性 ==== 这里就是去掉隐藏、系统、只读3个属性
	dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
	dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
	SetFileAttributes(FileName, dwFileAttributes);

	int delRet = DeleteFile(FileName);											// 删除文件
	if (delRet)
	{
		printf("File %s has been Deleted!\n\n", FileName);
		return TRUE;
	}
	else
	{
		printf("File %s is still alive! ErrorCode:%u\n\n", FileName,GetLastError());
		system("pause");
		return FALSE;
	}
}

// 判断文件是否为指定二进制文件
bool IsBinary(const char* pFileName)
{
	const char* pTemp = pFileName;								// 从第一个字符开始，不断比对剩下的字符串
	while (*pTemp != 0x00)										// 注意PIF为大写
	{
		if (!strcmp(pTemp, ".exe") || !strcmp(pTemp, ".PIF") || !strcmp(pTemp, ".com") || !strcmp(pTemp, ".src"))
		{
			return true;
		}
		++pTemp;
	}
	return false;
}

// 判断文件是否为指定脚本
bool IsScript(const char* pFileName)
{
	const char* pTemp = pFileName;
	while (*pTemp != 0x00)
	{
		if (!strcmp(pTemp, ".html") || !strcmp(pTemp, ".htm") || !strcmp(pTemp, ".asp") || !strcmp(pTemp, ".php") || !strcmp(pTemp, ".jsp") || !strcmp(pTemp, ".aspx"))
		{
			return true;
		}
		++pTemp;
	}
	return false;
}

// 根据路径名返回文件名
char* GetFilename(char* p)
{
	int x = strlen(p);
	char ch = '\\';
	char* q = strrchr(p, ch) + 1;
	return q;
}

// 修复感染二进制文件
BOOL FixBinaryFile(char* pStrFilePath)
{
	CHAR* pFilebuf = NULL;
	HANDLE hFile = CreateFile(pStrFilePath,									// 打开受感染文件
		GENERIC_READ | GENERIC_WRITE,
		FALSE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "Open infected file failed!", "WTF!", NULL);
		return 0;
	}

	DWORD FileSize = GetFileSize(hFile, NULL);								// 获取感染后文件大小
	pFilebuf = new CHAR[FileSize]{};										// 申请个数组用来保存
	DWORD dwCount = 1;
	BOOL bRet = ReadFile(hFile, pFilebuf, FileSize, &dwCount, NULL);		// 将感染文件读入内存
	if (!bRet)																// 读取出现错误
	{
		CloseHandle(hFile);
		delete pFilebuf;
		return FALSE;
	}
	char* pFileOffset = pFilebuf + SizeOfVirusFile_Bytes;					// 被感染文件的前面，0x7531为病毒源文件大小，1ffff字节为病毒脱壳后的文件
	char* p = pStrFilePath;
	int FileNameLength = strlen(GetFilename(p));							// 获取文件名长度

	SetFilePointer(hFile, 0, 0, FILE_BEGIN);								// 0x7531是病毒的大小,脱壳前的
	if (SizeOfVirusFile_Bytes==INVALID_FILE_SIZE)
	{
		//SizeOfVirusFile_Bytes = 0x7531;  //预设值1
		SizeOfVirusFile_Bytes = 0x18200;  //预设值2							// 0x18200是病毒的大小,脱壳后的
	}
	WriteFile(hFile, pFileOffset, FileSize - SizeOfVirusFile_Bytes - FileNameLength - 2, &dwCount, NULL);	// 感染标志的长度影响因子为目标文件的文件名长度
	SetEndOfFile(hFile);
	FixBinaryFileNumber++;													// 计数器统计修复个数
	CloseHandle(hFile);

	delete[] pFilebuf;
	return TRUE;
}

// 修复感染脚本文件
bool FixScriptFile(const char* pstrFilePath)
{
	CHAR* pFilebuf = NULL;
	HANDLE hFile = CreateFile(pstrFilePath,
		GENERIC_READ | GENERIC_WRITE,
		FALSE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "Open file failed!", "WTF", NULL);
		return 0;
	}
	DWORD FileSize = GetFileSize(hFile, NULL);
	pFilebuf = new CHAR[FileSize]{};
	DWORD dwCount = 1;
	BOOL bRet = ReadFile(hFile, pFilebuf, FileSize, &dwCount, NULL);		// 文件读入内存
	if (!bRet)
	{
		CloseHandle(hFile);
		delete pFilebuf;
		return FALSE;
	}
	char* pFileOffset = pFilebuf;
	SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	WriteFile(hFile, pFilebuf, FileSize - 76, &dwCount, NULL);				// 删除最后75个字节
	SetEndOfFile(hFile);
	FixScriptFileNumber++;													// 计数器统计修复个数
	CloseHandle(hFile);
	delete[] pFilebuf;
	return TRUE;
}

// 将文件读入内存并获取大小
char* GetFileBuf(char* pstrFilePath, _Out_ DWORD* FileSize)
{
	char* pFilebuf = NULL;
	//打开文件获取句柄
	HANDLE hFile = CreateFile(pstrFilePath,
		GENERIC_READ,
		FALSE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("File Open Faild!\n\n");
		return 0;
	}

	//获取文件大小
	*FileSize = GetFileSize(hFile, NULL);

	pFilebuf = new char[*FileSize] {};
	//读文件
	DWORD dwCount = 1;
	BOOL bRet = ReadFile(hFile, pFilebuf, *FileSize, &dwCount, NULL);

	if (bRet)
	{
		CloseHandle(hFile);
		return pFilebuf;
	}
	//释放资源
	CloseHandle(hFile);
	delete pFilebuf;
	return 0;

}

// 是否是被感染的二进制文件,被感染文件最后一个字节为01,向前找到00的后五个字节是WhBoy
bool IsInfectedBinaryFile(char* pstrFilePath)
{
	CHAR* pFileBuf = NULL;
	DWORD dwFileSize = 0;
	pFileBuf = GetFileBuf(pstrFilePath, &dwFileSize);
	if (pFileBuf == 0)
	{
		return false;
	}
	BYTE* pFileOffset = (BYTE*)pFileBuf;
	*pFileOffset;
	pFileOffset += (dwFileSize - 1);

	if (*pFileOffset != 0x01)									// 判断是否为0x01，不是的话就没感染
	{
		delete[] pFileBuf;
		return  false;
	}
	while (*pFileOffset != 0x00)
	{
		--pFileOffset;
	}
	pFileOffset++;
	CHAR temp[6] = { 0 };
	memcpy_s(temp, 5, pFileOffset, 5);
	if (!strcmp(temp, "WhBoy"))
	{
		delete[] pFileBuf;
		return  true;
	}
	delete[] pFileBuf;
	return  false;
}

// 是否是被感染的脚本文件
bool IsInfectedScriptFIle(char* pstrFilePath)
{
	CHAR* pFileBuf = NULL;
	DWORD dwFileSize = 0;
	pFileBuf = GetFileBuf(pstrFilePath, &dwFileSize);
	if (pFileBuf == 0)
	{
		return 0;
	}
	BYTE* pFileOffset = (BYTE*)pFileBuf;
	*pFileOffset;
	pFileOffset += (dwFileSize - 64);

	CHAR temp[32] = { 0 };
	memcpy_s(temp, 31, pFileOffset, 31);
	if (!lstrcmp(temp, "http://www.ac86.cn/66/index.htm"))
	{
		delete[] pFileBuf;
		return  TRUE;
	}
	delete[] pFileBuf;
	return  FALSE;
}

// 遍历全盘修复文件
DWORD WINAPI Delini_FixInfectedFiles(const char* lpszPath)
{
	WIN32_FIND_DATA stFindFile;
	HANDLE hFindFile;

	char szPath[MAX_PATH];
	char szFindFile[MAX_PATH];
	char szSearch[MAX_PATH];
	const char* szFilter;
	int len;
	int ret = 0;

	szFilter = "*.*";
	strcpy(szPath, lpszPath);
	len = lstrlen(szPath);
	if (szPath[len - 1] != '\\')
	{
		szPath[len] = '\\';
		szPath[len + 1] = '\0';
	}
	strcpy(szSearch, szPath);
	strcat(szSearch, szFilter);

	hFindFile = FindFirstFile(szSearch, &stFindFile);
	if (hFindFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			strcpy(szFindFile, szPath);
			strcat(szFindFile, stFindFile.cFileName);

			if (stFindFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (stFindFile.cFileName[0] != '.')
				{
					Delini_FixInfectedFiles(szFindFile);
				}
			}
			else
			{
				if (!strcmp(stFindFile.cFileName, "Desktop_.ini"))						// 删除Desktop_.ini
				{

					DWORD dwFileAttributes = GetFileAttributes(szFindFile);				// 去除文件的隐藏、系统以及只读属性
					dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
					dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
					dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
					SetFileAttributes(szFindFile, dwFileAttributes);

					BOOL bRet = DeleteFile(szFindFile);
					if (bRet)
					{
						printf("\"%s\"_____deleted!\n", szFindFile);
						DelDesktop_iniFileNumber++;										// 计数器统计个数
					}
					else
					{
						printf("Deleted \"%s\" failed!\n", szFindFile);
					}
				}
				else if (IsBinary(stFindFile.cFileName))									//判断是否是二进制文件
				{
					if (IsInfectedBinaryFile(szFindFile))
					{
						// printf("%s infected!\n", szFindFile);
						if (FixBinaryFile(szFindFile))
						{
							printf("\"%s\"_____fixed!\n", szFindFile);
						}
						else
						{
							printf("Fix \"%s\" failed!\n", szFindFile);
						}
					}
					else
					{
						printf("\"%s\"_____normal!\n\n", szFindFile);
					}
				}
				else if (IsScript(stFindFile.cFileName))									//判断是否是脚本文件
				{
					if (IsInfectedScriptFIle(szFindFile))
					{
						// printf("%s infected!\n", szFindFile);
						if (FixScriptFile(szFindFile))
						{
							printf("\"%s\"_____fixed!\n", szFindFile);
						}
						else
						{
							printf("Fix \"%s\" failed!!!!!\n", szFindFile);
						}
					}
					else
					{
						printf("\"%s\"_____normal!\n", szFindFile);
					}
				}
			}
			ret = FindNextFile(hFindFile, &stFindFile);
		} while (ret != 0);
	}

	FindClose(hFindFile);
	return 0;
}

// 选择病毒源文件，获取病毒源文件大小
void SelectVirusFile_GetVirusSize()
{
	// 选择Virus文件
	OPENFILENAMEA ofn;
	memset(path, 0, MAX_PATH);
	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.lpstrFile = path;																	// path
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = "*.exe\0*.exe\0";
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (!GetOpenFileName(&ofn)) {															// 如果打开文件错误
		MessageBox(NULL, "Open file failed!", NULL, MB_OK);
		exit(0);																			// 退出所有进程
	}
	// 获取文件句柄,映射到内存
	HANDLE hFile = CreateFileA(path, GENERIC_ALL, 3u, NULL, OPEN_EXISTING, 0x80u, 0);		// path，第一个3u表示共享读写
	if (hFile==INVALID_HANDLE_VALUE)
	{
		printf("%u\n", GetLastError());
		MessageBox(NULL, "FileHandle Invalid!", NULL, MB_OK);
		ExitProcess(0);
	}
	DWORD dwFileSize = GetFileSize(hFile, NULL);											// 获取文件大小
	if (dwFileSize==INVALID_FILE_SIZE)
	{
		printf("%u\n", GetLastError());
		MessageBox(NULL, "FileSize Invalid!", NULL, MB_OK);
		CloseHandle(hFile);
		ExitProcess(0);
	}
	else
	{
		SizeOfVirusFile_Bytes = dwFileSize;
		CloseHandle(hFile);
	}
}



int main() {

	//杀死病毒进程
	KillPandaProcess("spo0lsv.exe");

	//选择病毒文件，获取其大小，可能会失败
	SelectVirusFile_GetVirusSize();

	//修复注册表
	FixReg();								
					

	//删除定时启动文件
	DelSPecificFile("C:\\autorun.inf");										// 删除C盘根目录下的文件
	DelSPecificFile("C:\\setup.exe");
	DelSPecificFile("C:\\Windows\\System32\\drivers\\spo0lsv.exe");
	DelSPecificFile("C:\\Windows\\System32\\spo0lsv.exe");
	

	////修复被感染的exe文件
	//vector<WCHAR*>vec_FilePath;
	////获取磁盘盘符
	//WCHAR buf[10] = {};
	//GetLogicalDriveStringsW(10, buf);
	//WCHAR* p = buf;
	//while (*p != 0)
	//{
	//	//遍历
	//	FilePathCollection(p, vec_FilePath);
	//	p += wcslen(p) + 1;
	//}

	CHAR buf[10] = {};
	GetLogicalDriveStrings(10, buf);
	CHAR* p = buf;
	while (*p != 0)
	{
		//遍历
		Delini_FixInfectedFiles(p);
		p += strlen(p) + 1;
	}
			
	printf("\n==================YOUR PC IS CLEAR !=====================\n");
	printf("\n*********************** REPORT **************************\n");// 修复报告
	printf("The size of Virus file is %d bytes\n", SizeOfVirusFile_Bytes);
	printf("Fix binary files :%d \n", FixBinaryFileNumber);
	printf("Fix script files :%d \n", FixScriptFileNumber);
	printf("Del Desktop_.ini :%d \n", DelDesktop_iniFileNumber);
	printf("*********************** REPORT **************************\n\n");// 修复报告

	system("pause");

}