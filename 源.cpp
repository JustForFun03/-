#include <stdio.h>
#include <atlstr.h> //����CString
#include <vector>
#include <windows.h>
#include <Tlhelp32.h>
#pragma warning(disable : 4996) //��������strcyp�Ȳ���ȫ��������
using std::vector;

//#include <iostream>  //���ڿ���̨��ӡ����
//#include <shlobj_core.h>

//DWORD dwSize=0;
//char* pBuf = NULL;
//BOOL loadFile(WCHAR* Arr_PeFilePath) {
//	HANDLE hFile = CreateFileW(Arr_PeFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//	
//	if (hFile==INVALID_HANDLE_VALUE)
//	{
//		printf("��ȡ%Sʧ��\n", Arr_PeFilePath);
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


//ͨ������������ʾ��ȡ�ļ�·��
//void GetFilePathCreateProcess() {
//
//	HWND hConsoleWnd = FindWindowW(L"ConsoleWindowClass", NULL);
//	WCHAR FilePathName[MAX_PATH * 2]{};
//
//	//��ȡ�ļ�·����
//	OPENFILENAMEW file = { 0 };
//	file.hwndOwner = hConsoleWnd;
//	file.lStructSize = sizeof(file);
//	file.lpstrFilter = L"�����ļ�(*.*)\0*.*\0Exe�ļ�(*.exe)\0*.exe\0\0";//Ҫѡ����ļ���׺ 
//	file.lpstrInitialDir = L"";//Ĭ�ϵ��ļ�·�� 
//	file.lpstrFile = FilePathName;//����ļ����ƵĻ����� 
//	file.nMaxFile = _countof(FilePathName);
//	file.nFilterIndex = 0;
//	file.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;//��־����Ƕ�ѡҪ����OFN_ALLOWMULTISELECT
//	BOOL bSel = GetOpenFileNameW(&file);
//	CString filePath = file.lpstrFile;
//
//	STARTUPINFO si{};         //������Ϣ�ṹ��
//	PROCESS_INFORMATION pi{}; //������Ϣ�ṹ��
//	si.cb = sizeof(STARTUPINFO);  //��ʼ��������Ϣ�ṹ���С
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

//����exe  
//void FilePathCollection(const WCHAR* BasePath, vector<WCHAR*>& vec_FilePath) {
//
//	//��ȡ�����ļ����������ļ�·����Ϣ
//	WIN32_FIND_DATAW  wfd = {};
//	setlocale(LC_ALL, "CHS"); // �����ַ������ʽ
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
//					//��ѡdll�ļ�����
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
//					//���浽vector��
//					if (flag)
//					{
//						CStringW temp;
//						temp.Format(L"%s\\%s", BasePath, wfd.cFileName);
//						WCHAR* pTemp = new WCHAR[wcslen(temp.GetBuffer()) + 1];
//						wcscpy_s(pTemp, wcslen(temp.GetBuffer()) + 1, temp.GetBuffer());
//						//vec_FilePath.push_back(pTemp);
//
//						//��ȡ����Ⱦexe���ڴ�
//						BOOL Ret=loadFile(pTemp);
//
//						if (Ret)
//						{
//							continue;
//						}
//						//������ȡ����Ⱦ������ļ���С��ASCII��
//						//ת��������
//
//
//						//�����ֱ�Ӹ��Ƶ���β
//
//						//��λ��0x18200h����ѭ��д�뵽���ļ� wfd.cFileName
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
//									printf("%S�Ѿ��޸�\n", pTemp);
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


// ȫ�ֱ�������ͳ��
int FixBinaryFileNumber = 0;
int FixScriptFileNumber = 0;
int DelDesktop_iniFileNumber = 0;
int SizeOfVirusFile_Bytes = 0;
char path[MAX_PATH];														// ���没���ļ�·��

// ����ָ�����̣�����ΪĿ������ַ���
BOOL KillPandaProcess(const char* pszProcessName)
{
	BOOL bKill = FALSE;
	HANDLE hProcess;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)									// �����ȡ���̿���ʧ�ܣ����� FALSE
	{
		return bKill;
	}
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);
	BOOL bRet = Process32First(hProcessSnap, &pe);								// ��ȡ��һ������
	while (bRet)
	{
		if (strcmp(pe.szExeFile, pszProcessName) == 0)
		{
			bKill = TRUE;
			hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
			int ret = TerminateProcess(hProcess, 1);							// ��ֹ����
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

// �޸�ע���
void FixReg()
{
	// ɾ��svcshare
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
	// �޸��ļ���������ʾ����CheckedValue��ֵ����Ϊ1
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

// ɾ��ָ���ļ�
BOOL DelSPecificFile(const char* FileName)
{
	// ȥ���ļ������ء�ϵͳ�Լ�ֻ������
	DWORD dwFileAttributes = GetFileAttributes(FileName);						// ��ȡ�ļ�����
	dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;									// &=~ ��ȥ�����ԣ�| ���������� ==== �������ȥ�����ء�ϵͳ��ֻ��3������
	dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
	dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
	SetFileAttributes(FileName, dwFileAttributes);

	int delRet = DeleteFile(FileName);											// ɾ���ļ�
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

// �ж��ļ��Ƿ�Ϊָ���������ļ�
bool IsBinary(const char* pFileName)
{
	const char* pTemp = pFileName;								// �ӵ�һ���ַ���ʼ�����ϱȶ�ʣ�µ��ַ���
	while (*pTemp != 0x00)										// ע��PIFΪ��д
	{
		if (!strcmp(pTemp, ".exe") || !strcmp(pTemp, ".PIF") || !strcmp(pTemp, ".com") || !strcmp(pTemp, ".src"))
		{
			return true;
		}
		++pTemp;
	}
	return false;
}

// �ж��ļ��Ƿ�Ϊָ���ű�
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

// ����·���������ļ���
char* GetFilename(char* p)
{
	int x = strlen(p);
	char ch = '\\';
	char* q = strrchr(p, ch) + 1;
	return q;
}

// �޸���Ⱦ�������ļ�
BOOL FixBinaryFile(char* pStrFilePath)
{
	CHAR* pFilebuf = NULL;
	HANDLE hFile = CreateFile(pStrFilePath,									// ���ܸ�Ⱦ�ļ�
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

	DWORD FileSize = GetFileSize(hFile, NULL);								// ��ȡ��Ⱦ���ļ���С
	pFilebuf = new CHAR[FileSize]{};										// �����������������
	DWORD dwCount = 1;
	BOOL bRet = ReadFile(hFile, pFilebuf, FileSize, &dwCount, NULL);		// ����Ⱦ�ļ������ڴ�
	if (!bRet)																// ��ȡ���ִ���
	{
		CloseHandle(hFile);
		delete pFilebuf;
		return FALSE;
	}
	char* pFileOffset = pFilebuf + SizeOfVirusFile_Bytes;					// ����Ⱦ�ļ���ǰ�棬0x7531Ϊ����Դ�ļ���С��1ffff�ֽ�Ϊ�����ѿǺ���ļ�
	char* p = pStrFilePath;
	int FileNameLength = strlen(GetFilename(p));							// ��ȡ�ļ�������

	SetFilePointer(hFile, 0, 0, FILE_BEGIN);								// 0x7531�ǲ����Ĵ�С,�ѿ�ǰ��
	if (SizeOfVirusFile_Bytes==INVALID_FILE_SIZE)
	{
		//SizeOfVirusFile_Bytes = 0x7531;  //Ԥ��ֵ1
		SizeOfVirusFile_Bytes = 0x18200;  //Ԥ��ֵ2							// 0x18200�ǲ����Ĵ�С,�ѿǺ��
	}
	WriteFile(hFile, pFileOffset, FileSize - SizeOfVirusFile_Bytes - FileNameLength - 2, &dwCount, NULL);	// ��Ⱦ��־�ĳ���Ӱ������ΪĿ���ļ����ļ�������
	SetEndOfFile(hFile);
	FixBinaryFileNumber++;													// ������ͳ���޸�����
	CloseHandle(hFile);

	delete[] pFilebuf;
	return TRUE;
}

// �޸���Ⱦ�ű��ļ�
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
	BOOL bRet = ReadFile(hFile, pFilebuf, FileSize, &dwCount, NULL);		// �ļ������ڴ�
	if (!bRet)
	{
		CloseHandle(hFile);
		delete pFilebuf;
		return FALSE;
	}
	char* pFileOffset = pFilebuf;
	SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	WriteFile(hFile, pFilebuf, FileSize - 76, &dwCount, NULL);				// ɾ�����75���ֽ�
	SetEndOfFile(hFile);
	FixScriptFileNumber++;													// ������ͳ���޸�����
	CloseHandle(hFile);
	delete[] pFilebuf;
	return TRUE;
}

// ���ļ������ڴ沢��ȡ��С
char* GetFileBuf(char* pstrFilePath, _Out_ DWORD* FileSize)
{
	char* pFilebuf = NULL;
	//���ļ���ȡ���
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

	//��ȡ�ļ���С
	*FileSize = GetFileSize(hFile, NULL);

	pFilebuf = new char[*FileSize] {};
	//���ļ�
	DWORD dwCount = 1;
	BOOL bRet = ReadFile(hFile, pFilebuf, *FileSize, &dwCount, NULL);

	if (bRet)
	{
		CloseHandle(hFile);
		return pFilebuf;
	}
	//�ͷ���Դ
	CloseHandle(hFile);
	delete pFilebuf;
	return 0;

}

// �Ƿ��Ǳ���Ⱦ�Ķ������ļ�,����Ⱦ�ļ����һ���ֽ�Ϊ01,��ǰ�ҵ�00�ĺ�����ֽ���WhBoy
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

	if (*pFileOffset != 0x01)									// �ж��Ƿ�Ϊ0x01�����ǵĻ���û��Ⱦ
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

// �Ƿ��Ǳ���Ⱦ�Ľű��ļ�
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

// ����ȫ���޸��ļ�
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
				if (!strcmp(stFindFile.cFileName, "Desktop_.ini"))						// ɾ��Desktop_.ini
				{

					DWORD dwFileAttributes = GetFileAttributes(szFindFile);				// ȥ���ļ������ء�ϵͳ�Լ�ֻ������
					dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
					dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
					dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
					SetFileAttributes(szFindFile, dwFileAttributes);

					BOOL bRet = DeleteFile(szFindFile);
					if (bRet)
					{
						printf("\"%s\"_____deleted!\n", szFindFile);
						DelDesktop_iniFileNumber++;										// ������ͳ�Ƹ���
					}
					else
					{
						printf("Deleted \"%s\" failed!\n", szFindFile);
					}
				}
				else if (IsBinary(stFindFile.cFileName))									//�ж��Ƿ��Ƕ������ļ�
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
				else if (IsScript(stFindFile.cFileName))									//�ж��Ƿ��ǽű��ļ�
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

// ѡ�񲡶�Դ�ļ�����ȡ����Դ�ļ���С
void SelectVirusFile_GetVirusSize()
{
	// ѡ��Virus�ļ�
	OPENFILENAMEA ofn;
	memset(path, 0, MAX_PATH);
	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.lpstrFile = path;																	// path
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = "*.exe\0*.exe\0";
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (!GetOpenFileName(&ofn)) {															// ������ļ�����
		MessageBox(NULL, "Open file failed!", NULL, MB_OK);
		exit(0);																			// �˳����н���
	}
	// ��ȡ�ļ����,ӳ�䵽�ڴ�
	HANDLE hFile = CreateFileA(path, GENERIC_ALL, 3u, NULL, OPEN_EXISTING, 0x80u, 0);		// path����һ��3u��ʾ�����д
	if (hFile==INVALID_HANDLE_VALUE)
	{
		printf("%u\n", GetLastError());
		MessageBox(NULL, "FileHandle Invalid!", NULL, MB_OK);
		ExitProcess(0);
	}
	DWORD dwFileSize = GetFileSize(hFile, NULL);											// ��ȡ�ļ���С
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

	//ɱ����������
	KillPandaProcess("spo0lsv.exe");

	//ѡ�񲡶��ļ�����ȡ���С�����ܻ�ʧ��
	SelectVirusFile_GetVirusSize();

	//�޸�ע���
	FixReg();								
					

	//ɾ����ʱ�����ļ�
	DelSPecificFile("C:\\autorun.inf");										// ɾ��C�̸�Ŀ¼�µ��ļ�
	DelSPecificFile("C:\\setup.exe");
	DelSPecificFile("C:\\Windows\\System32\\drivers\\spo0lsv.exe");
	DelSPecificFile("C:\\Windows\\System32\\spo0lsv.exe");
	

	////�޸�����Ⱦ��exe�ļ�
	//vector<WCHAR*>vec_FilePath;
	////��ȡ�����̷�
	//WCHAR buf[10] = {};
	//GetLogicalDriveStringsW(10, buf);
	//WCHAR* p = buf;
	//while (*p != 0)
	//{
	//	//����
	//	FilePathCollection(p, vec_FilePath);
	//	p += wcslen(p) + 1;
	//}

	CHAR buf[10] = {};
	GetLogicalDriveStrings(10, buf);
	CHAR* p = buf;
	while (*p != 0)
	{
		//����
		Delini_FixInfectedFiles(p);
		p += strlen(p) + 1;
	}
			
	printf("\n==================YOUR PC IS CLEAR !=====================\n");
	printf("\n*********************** REPORT **************************\n");// �޸�����
	printf("The size of Virus file is %d bytes\n", SizeOfVirusFile_Bytes);
	printf("Fix binary files :%d \n", FixBinaryFileNumber);
	printf("Fix script files :%d \n", FixScriptFileNumber);
	printf("Del Desktop_.ini :%d \n", DelDesktop_iniFileNumber);
	printf("*********************** REPORT **************************\n\n");// �޸�����

	system("pause");

}