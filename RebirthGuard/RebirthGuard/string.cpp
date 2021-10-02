
/********************************************
*											*
*	RebirthGuard/string.cpp - chztbby		*
*											*
********************************************/

#include "RebirthGuard.h"


//-------------------------------------------------------
//	strcmp
//-------------------------------------------------------
INT mystrcmp(CONST CHAR *p1, CONST CHAR *p2)
{
	CONST BYTE *s1 = (CONST BYTE*)p1;
	CONST BYTE *s2 = (CONST BYTE*)p2;
	BYTE c1, c2;
	do
	{
		c1 = (BYTE)*s1++;
		c2 = (BYTE)*s2++;
		if (c1 == '\0')
			return c1 - c2;
	} while (c1 == c2);
	return c1 - c2;
}


//-------------------------------------------------------
//	strcat
//-------------------------------------------------------
CHAR* mystrcat(CHAR* s1, CONST CHAR* s2)
{
	CHAR *cp;
	cp = s1;
	while (*cp != '\0')
		cp++;
	while ((*cp++ = *s2++) != '\0');

	return (s1);
}


//-------------------------------------------------------
//	wcsistr
//-------------------------------------------------------
WCHAR* mywcsistr(CONST WCHAR* pszSrc, CONST WCHAR* pszSearch)
{
	if (pszSrc && pszSearch)
	{
		CONST WCHAR* s, *sub;
		for (; *pszSrc; pszSrc++)
		{
			for (sub = pszSearch, s = pszSrc; *sub && *s; sub++, s++)
			{
				WCHAR ms, msub;
				if (*s >= 'a' && *s <= 'z')	ms = *s - 0x20;
				else						ms = *s;
				if (*sub >= 'a' && *sub <= 'z') msub = *sub - 0x20;
				else							msub = *sub;
				if (ms != msub) break;
			}

			if (*sub == 0)
				return (WCHAR*)pszSrc;
		}
	}
	return NULL;
}


//-------------------------------------------------------
//	wcscpy
//-------------------------------------------------------
WCHAR* mywcscpy(WCHAR* s1, CONST WCHAR* s2)
{
	WCHAR *cp;
	cp = s1;
	while ((*cp++ = *s2++) != L'\0');

	return (s1);
}


//-------------------------------------------------------
//	wcscat
//-------------------------------------------------------
WCHAR* mywcscat(WCHAR* s1, CONST WCHAR* s2)
{
	WCHAR *cp;
	cp = s1;
	while (*cp != L'\0')
		cp++;
	while ((*cp++ = *s2++) != L'\0');

	return (s1);
}