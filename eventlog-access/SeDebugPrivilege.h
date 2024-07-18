//-----------------------------------------------------------------------------------------------------------
// SeDebugPrivilege.h
//
// Utility for enabling/disabling SeDebugPrivilege
//-----------------------------------------------------------------------------------------------------------
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>


EXTERN_C_START

/**
 * @brief Enables or Disables SeDebugPrivilege
 * 
 * @remark This function could be generalized to enable/disable any of the Windows token privileges by simply
 *      passing the privilege as a parameter. 
 * 
 * @param Enable Boolean flag indicating that the privilege should be enabled. If false, privilege is disabled
 * 
 * @return Returns true if the requested action succeeded. Prints error message and returns false on error 
 */
bool SetDebugPrivilege(bool Enable);

EXTERN_C_END
