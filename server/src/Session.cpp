/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 05/01/2022
http://aneta.sf.net

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
copyright notice, this list of conditions and the
following disclaimer.

* Redistributions in binary form must reproduce the
above copyright notice, this list of conditions
and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
#include "stdafx.h"
#include "Session.h"

BEGIN_ASYN_MESSAGE_MAP(CSession)
	ON_EVENT_NOTIFY(OnEventNotify, IAsynIoOperation)
	ON_QUERY_RESULT(OnQueryResult, IAsynIoOperation)
END_ASYN_MESSAGE_MAP()
/////////////////////////////////////////////////////////////////////////////
HRESULT CSession::OnEventNotify( uint64_t lParam1, uint64_t lParam2, IAsynIoOperation *lpAsynIoOperation )
{
    return m_spAsynFrame->PostMessage(0, AF_EVENT_NOTIFY, m_lparam1, m_lparam2, 0);
}

HRESULT CSession::OnQueryResult( uint64_t lParam1, uint64_t lParam2, IAsynIoOperation **ppAsynIoOperation )
{
#ifdef _DEBUG
    printf("pSocket: %p session[%p] transmit: %I64d\n", (void *)m_lparam2, (void *)lParam1, lParam2);
#endif
    return S_OK;
}