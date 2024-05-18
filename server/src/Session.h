#ifndef __SESSION_H__
#define __SESSION_H__
/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 01/15/2024
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
#include <frame/AsynNetwork_internal.h>
using namespace asynsdk;

class CSession : public asyn_message_events_impl
{
public:
    CSession(IAsynFrame *lpAsynFrame, uint64_t lparam1, uint64_t lparam2, IAsynIoBridge *lpAsynPipes)
    {
        m_lparam1 = lparam1;
        m_lparam2 = lparam2;
        m_spAsynFrame = lpAsynFrame;
        m_spAsynPipes = lpAsynPipes;
    }
    virtual ~CSession()
    {
        asyn_message_events_impl::Stop(0);
    }

public: // interface of asyn_message_events_impl
    DECLARE_ASYN_MESSAGE_MAP(CSession)
    HRESULT OnEventNotify( uint64_t lParam1, uint64_t lParam2, IAsynIoOperation  *lpAsynIoOperation );
    HRESULT OnQueryResult( uint64_t lParam1, uint64_t lAction, IAsynIoOperation **ppAsynIoOperation );

public:
    void Start()
    {
        m_spAsynPipes->Invoke(0, asyn_message_events_impl::GetAsynMessageEvents());
    }

protected:
    CComPtr<IAsynIoBridge> m_spAsynPipes;
    CComPtr<IAsynFrame   > m_spAsynFrame;
    uint64_t m_lparam1;
    uint64_t m_lparam2;
};

#endif//__SESSION_H__
