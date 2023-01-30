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
#include "Service.h"
#include "Session.h"

BEGIN_ASYN_MESSAGE_MAP(CService)
	ON_IOMSG_NOTIFY(OnIomsgNotify)
	ON_QUERY_RESULT(OnQueryResult, IKeyvalSetter)
 	ON_EVENT_NOTIFY(OnEventNotify, IUnknown)
END_ASYN_MESSAGE_MAP()
/////////////////////////////////////////////////////////////////////////////
HRESULT CService::OnIomsgNotify( uint64_t lparam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation )
{
    uint32_t lErrorCode = NO_ERROR;
    lpAsynIoOperation->GetCompletedResult(&lErrorCode, 0, 0);

    switch(lAction)
    {
        case Io_connect:
        {
            if( lErrorCode != NO_ERROR )
            {
                printf("pSocket: %p is deleted, error: %d\n", (void *)lparam1, lErrorCode);
                break;
            }
            else
            {
                std::string host; asynsdk::CStringSetterRef temp(1, &host);
                PORT        port;
                CComPtr<IAsynNetIoOperation> spAsynIoOperation;
                lpAsynIoOperation->QueryInterface(IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
                spAsynIoOperation->GetPeerAddress(&temp, 0, &port, 0);

                CComPtr<IAsynIoBridge> spAsynIoBridge;
                lpAsynIoOperation->GetCompletedObject(1, IID_IAsynIoBridge, (void **)&spAsynIoBridge);

                CSession *pSession = new CSession(m_spAsynFrame, (uint64_t)(this), lparam1, spAsynIoBridge);
                m_arSock2AgentSessions[lparam1].reset(pSession);
                printf("pSocket: %p session[%p] start to transmit[%s:%d]\n", (void *)lparam1, spAsynIoBridge.p, host.empty() ? "*" : host.c_str(), port);
                pSession->Start();
                break;
            }
        }

        case Io_acceptd:
        {
            PORT bindport = (PORT)lparam1;
            if( lErrorCode != NO_ERROR )
            {
                printf("accept[%d], error: %d\n", bindport, lErrorCode);

                std::map<PORT, std::pair<std::string, CComPtr<IAsynTcpSocketListener> > >::iterator ia = m_arPort2ProtocolAsynTcpSocketListeners.find(bindport);
                if( ia != m_arPort2ProtocolAsynTcpSocketListeners.end()) return ia->second.second->Accept(lpAsynIoOperation);

                HRESULT r1 = m_spAsynNetAgent->OnMessage(AF_IOMSG_NOTIFY, bindport, lAction, (IUnknown **)&lpAsynIoOperation);
                m_arPort2AsynTcpSocketListeners.erase(bindport);
                break;
            }
            else
            {// 新客户端接入
                uint32_t af;
                std::string host; asynsdk::CStringSetterRef temp(1, &host);
                PORT        port;
                CComPtr<IAsynNetIoOperation> spAsynIoOperation;
                lpAsynIoOperation->QueryInterface(IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
                spAsynIoOperation->GetPeerAddress(&temp, 0, &port, &af);

                std::map<PORT, CComPtr<IAsynTcpSocketListener> >::iterator it = m_arPort2AsynTcpSocketListeners.find(bindport);
                if( it != m_arPort2AsynTcpSocketListeners.end() )
                {
                    printf("accept[%d] from %s:%d\n", it->first, host.c_str(), port);
                    m_spAsynNetAgent->OnMessage(AF_IOMSG_NOTIFY, bindport, lAction, (IUnknown **)&lpAsynIoOperation);
                    m_arPort2AsynTcpSocketListeners.erase(it);
                    break;
                }
                else
                {
                    CComPtr<IAsynRawSocket  > spAsynNewSocket;
                    lpAsynIoOperation->GetCompletedObject(1, IID_IAsynRawSocket, (void **)&spAsynNewSocket);

                    std::map<PORT, std::pair<std::string, CComPtr<IAsynTcpSocketListener> > >::iterator ia = m_arPort2ProtocolAsynTcpSocketListeners.find(bindport);
                    printf("pSocket: %p is created from %s:%d[%s]\n", spAsynNewSocket.p, host.c_str(), port, ia->second.first.c_str());

                    lpAsynIoOperation->SetOpParam1((uint64_t)spAsynNewSocket.p);
                    m_spAsynNetAgent->Connect(spAsynNewSocket, STRING_from_string(ia->second.first), lpAsynIoOperation, 5000/*5sec*/);

                    CComPtr<IAsynIoOperation> spConnOperation;
                    m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, af, 0, IID_IAsynIoOperation, (void **)&spConnOperation);
                    spConnOperation->SetOpParam1((uint64_t)bindport);
                    return ia->second.second->Accept(spConnOperation);
                }
            }
        }
    }
    return E_NOTIMPL; //通知系统释放lpAsynIoOperation
}

HRESULT CService::OnEventNotify( uint64_t lparam1, uint64_t lparam2, IUnknown *object )
{
    if( lparam1 == (uint64_t)this)
    {
        printf("pSocket: %p is deleted\n", (void *)lparam2);
        m_arSock2AgentSessions.erase(lparam2);
    }
    return S_OK;
}

HRESULT CService::OnQueryResult( uint64_t lparam1, uint64_t lparam2, IKeyvalSetter **ppKeyval )
{
    if( lparam1 ) return E_NOTIMPL;
 
    asynsdk::CStringSetter d(1);
    ppKeyval[0]->Get(STRING_from_string(";dattype"), 0, 0, &d);

    asynsdk::CStringSetter c(1);
    ppKeyval[0]->Get(STRING_from_string(";context"), 0, 0, &c);

    asynsdk::CStringSetter a(1);
    ppKeyval[0]->Get(STRING_from_string(";af"     ), 0, 0, &a);

    std::string::size_type ipos;
    if((ipos = d.m_val.rfind("tcp.connect")) != std::string::npos )
    {// tcp.connect
        printf("pSocket: %p %s from %s\n", (void*)lparam2, c.m_val.c_str(), d.m_val.c_str());
        return S_OK;
    }
    if((ipos = d.m_val.rfind("tcp.bind"   )) != std::string::npos )
    {// tcp.bind
        printf("pSocket: %p %s from %s\n", (void*)lparam2, c.m_val.c_str(), d.m_val.c_str());
        std::string host = m_setsfile.get_string("globals", "host");
        PORT        port = 0;

        CComPtr<IAsynTcpSocketListener> spAsynTcpSocketListener;
        m_spAsynNetwork->CreateAsynTcpSocketListener(STRING_EX::null, &spAsynTcpSocketListener);
        spAsynTcpSocketListener->Open(m_spAsynFrameThread, atoi(a.m_val.c_str()), SOCK_STREAM, IPPROTO_TCP);
        spAsynTcpSocketListener->Bind(STRING_EX::null, 0, 0, 0);
        spAsynTcpSocketListener->GetSockAddress(0, 0, &port, 0);

        c.m_val = "tcp://" + (host.empty() ? std::string("*") : host) + ":" + std::to_string(port);
        printf("pSocket: %p %s\n", (void*)lparam2, c.m_val.c_str());
        ppKeyval[0]->Set(STRING_from_string(";context"), 0, STRING_from_string(c.m_val));
        m_arPort2AsynTcpSocketListeners[port] = spAsynTcpSocketListener;

        CComPtr<IAsynIoOperation> spAsynIoOperation;
        m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, 0, 0, IID_IAsynIoOperation, (void **)&spAsynIoOperation);
        m_spAsynFrameThread->BindAsynIoOperation(spAsynIoOperation, 0, 0, 30000/*30sec超时*/);

        spAsynIoOperation->SetOpParam1(port);
        spAsynTcpSocketListener->Accept(spAsynIoOperation);
        return S_OK;
    }
    if((ipos = d.m_val.rfind("udp.bind"   )) != std::string::npos )
    {// udp.bind
        printf("pSocket: %p %s from %s\n", (void*)lparam2, c.m_val.c_str(), d.m_val.c_str());
        
        std::string host = m_setsfile.get_string("globals", "host");
        PORT        port = 0;

        CComPtr<IAsynUdpSocket> spAsynUdpSocket;
        m_spAsynNetwork->CreateAsynUdpSocket(&spAsynUdpSocket);
        spAsynUdpSocket->Open(m_spAsynFrameThread, atoi(a.m_val.c_str()), SOCK_DGRAM, IPPROTO_UDP);
        spAsynUdpSocket->Bind(STRING_EX::null, 0, 0, 0);
        spAsynUdpSocket->GetSockAddress(0, 0, &port, 0);

        c.m_val = "udp://" + (host.empty() ? std::string("*") : host) + ":" + std::to_string(port);
        printf("pSocket: %p %s\n", (void*)lparam2, c.m_val.c_str());
        ppKeyval[0]->Set(STRING_from_string(";context"), 0, STRING_from_string(c.m_val));

        ppKeyval[0]->Set(STRING_from_string(";resultp"), 0, STRING_from_buffer(spAsynUdpSocket.p, 0));
        return S_OK;
    }

    if((ipos = d.m_val.rfind("ftp.stat"   )) != std::string::npos )
    {// ftpserver stat ack
        static const char *ftpstat = "Copyright (c) netsecsp 2012-2032, All rights reserved.\n"
                                     "Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated " STRING_UPDATETIME "\n"
                                     "http://aneta.sf.net\n";
        ppKeyval[0]->Set(STRING_from_string(";context"), 0, STRING_from_string(ftpstat));
        return S_OK;
    }

    if((ipos = d.m_val.rfind("cert.get"   )) != std::string::npos)
    {// cert.get
        if( m_cert_p12.empty()) return S_FALSE;
        ISsl *pSsl = (ISsl *)lparam2;
        STRING certandpasswd[2];
        certandpasswd[0] = STRING_from_string(m_cert_p12);
        certandpasswd[1] = STRING_from_string(m_password);
        pSsl->SetCryptContext(0, 0, certandpasswd);
        ppKeyval[0]->Set(STRING_from_string(";version"), 0, STRING_from_string(m_setsfile.get_string("ssl", "algo", "tls/1.0")));
        return S_OK;
    }

    if((ipos = d.m_val.rfind("cert.verify")) != std::string::npos)
    {// cert.verify
        return S_OK;
    }

    if((ipos = d.m_val.rfind("account.verify")) != std::string::npos )
    {// verify client: user[:pass]
        std::string::size_type ipos = c.m_val.find(':');
        std::string user = ipos == std::string::npos ? c.m_val : c.m_val.substr(0, ipos);
        std::string password = ipos == std::string::npos ? std::string("") : c.m_val.substr(ipos + 1);

        if(!m_setsfile.is_exist(user, "password") ||
            password != m_setsfile.get_string(user, "password"))
        {
            printf("pSocket: %p %s from %s result no\n", (void*)lparam2, c.m_val.c_str(), d.m_val.c_str());
            return S_FALSE;
        }
        else
        {
            printf("pSocket: %p %s from %s result ok\n", (void*)lparam2, c.m_val.c_str(), d.m_val.c_str());
            return S_OK;
        }
    }

    if((ipos = d.m_val.rfind("account.get"   )) != std::string::npos )
    {
        std::string user = c.m_val;
        if(!m_setsfile.is_exist(user, "password"))
        {
            printf("pSocket: %p %s from %s result no\n", (void*)lparam2, c.m_val.c_str(), d.m_val.c_str());
            return S_FALSE;
        }

        printf("pSocket: %p %s from %s result ok\n", (void*)lparam2, c.m_val.c_str(), d.m_val.c_str());
        ppKeyval[0]->Set(STRING_from_string(";context"), 0, STRING_from_string(user + ":" + m_setsfile.get_string(user, "password")));
        return S_OK;
    }
    return E_NOTIMPL;
}
