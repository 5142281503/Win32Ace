#include "stdafx.h"
#include <string>
#include <iostream>

int AddEveryoneAce(const std::string& in_What);
	
int RemoveEveryoneAce(const std::string& in_What);

namespace
{
	int
	ShowHelp(const std::string& in_App)
	{
		std::cout << in_App << " -add or -remove followed by the resource name. \r\neg -add \"c:\\test\" " << std::endl;
		return 1;
	}

	// returns ERROR_SUCCESS or 1 for error
	DWORD allow_everyone_access(const std::string& in_strPath, SE_OBJECT_TYPE in_object_type )
	{
		SECURITY_DESCRIPTOR* pSD = NULL;
		const DWORD dwErr = ::GetNamedSecurityInfo((LPSTR)in_strPath.c_str(), in_object_type, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, (PSECURITY_DESCRIPTOR *) &pSD);

		if ( ERROR_SUCCESS != dwErr || !pSD )
		{
			std::cerr << "GetNamedSecurityInfo() failed" << std::endl;
			return dwErr;
		}
		else
		{
			CSecurityDesc SecDesc( *pSD );
			LocalFree( pSD );
			pSD = NULL;
			
			CSid EveryoneSid( Sids::World() );

			CDacl AccessList;
			if ( !SecDesc.GetDacl( &AccessList ) )
			{
				std::cerr << "GetDacl() failed" << std::endl;
			}
			else
			{
				if ( !AccessList.AddAllowedAce( EveryoneSid, GENERIC_ALL, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE ) )
				{
					std::cerr << "AddAllowedAce() failed" << std::endl;
				}

				const DWORD dwModificationStatus = SetNamedSecurityInfo( (LPSTR)in_strPath.c_str(), 
																	in_object_type, 
																	DACL_SECURITY_INFORMATION, 
																	NULL, 
																	NULL, 
																	const_cast<const PACL>( AccessList.GetPACL() ), 
																	NULL);
				_ASSERT( dwModificationStatus == ERROR_SUCCESS );
				return  ( dwModificationStatus  );					
			}				
		}
		
		return 1;
	}
}


int _tmain(int argc, _TCHAR* argv[])
{
	if(argc < 3)
	{
		return ShowHelp(argv[0]);
	}

	const std::string argv1( argv[1] );
	const std::string argv2( argv[2] );

	if(argv1 == "-add")
		return AddEveryoneAce(argv2);
	else if(argv1 == "-remove")
		return RemoveEveryoneAce(argv2);

	return ShowHelp(argv[0]);
}

int 
AddEveryoneAce(const std::string& in_What)
{
	if(ERROR_SUCCESS != allow_everyone_access( in_What.c_str(), SE_FILE_OBJECT ))
	{
		std::cerr << "failed. make sure you are running me with sufficient privileges" << std::endl;
	}
	else
	{
		std::cout << "success" << std::endl;
	}

	return 1;
}


int 
RemoveEveryoneAce(const std::string& in_What)
{
	CSecurityDesc sd;

	SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION ;

	if (AtlGetSecurityDescriptor(in_What.c_str(), SE_FILE_OBJECT, &sd))
	{
		CDacl dacl;
		bool bPresent = false;
		bool bDefaulted = false;
		sd.GetDacl(&dacl, &bPresent, &bDefaulted);

		if(dacl.IsNull())
		{
			std::cerr << "ACL is NULL, nothing to do" << std::endl;
		}
		else if (dacl.IsEmpty())
		{
			std::cerr << "ACL is EMPTY, nothing to do" << std::endl;
		}
		else
		{
			std::cout << "Ace Count: " <<  dacl.GetAceCount() << std::endl;

			CSid EveryoneSid( Sids::World() );

			bool bGoAhead = false;

			for (UINT i=0; i < dacl.GetAceCount(); ++i)
			{
				CSid sid;
				ACCESS_MASK mask;
				BYTE type;
				BYTE flags;
				GUID guidObjectType;
				GUID guidInheritedObjectType;				

				dacl.GetAclEntry(i, &sid, &mask, &type, &flags, &guidObjectType, &guidInheritedObjectType);

				std::cout << "Ace " <<  i << " is " << sid.AccountName() << std::endl;
				
				if(EveryoneSid == sid)
				{
					dacl.RemoveAce(i);
					bGoAhead = true;
					break;
				}
			}

			if(bGoAhead)
			{
 				const DWORD dwModificationStatus = SetNamedSecurityInfo( (LPSTR)in_What.c_str(), 
													SE_FILE_OBJECT, 
													DACL_SECURITY_INFORMATION, 
													NULL, 
													NULL, 
													const_cast<const PACL>( dacl.GetPACL() ), 
													NULL);

				
				if ( dwModificationStatus != ERROR_SUCCESS )
				{
					std::cerr << "SetNamedSecurityInfo() failed" << std::endl;
				}
				else
				{
					std::cout << "success" << std::endl;
					RemoveEveryoneAce(in_What);
					return ERROR_SUCCESS;
				}
			}
			else
			{
				std::cout << "there was no everyone ACE to remove...nothing to do" << std::endl;
			}
		}
	}
	else
	{
		std::cerr << "AtlGetSecurityDescriptor() failed" << std::endl;
	}

	return 1;
}