#ifndef __SERVICE_H__
#define __SERVICE_H__
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
#include <map >
#include <list>
#include <memory>
#include <frame/AsynNeta_internal.h>
#include <frame/asm/INet.h>
#include <frame/asm/ISsl.h>
#include "setting.h"
#include "Session.h"
using namespace asynsdk;

class CService : public asyn_message_events_impl
{
public:
    CService(InstancesManager *lpInstanceManager, setting &configure)
        : m_setsfile(configure), m_spInstanceManager(lpInstanceManager)
    {
        m_spInstanceManager->GetInstance(STRING_from_string(IN_AsynNetAgent), IID_IAsynNetAgent, (void **)&m_spAsynNetAgent);
        m_spInstanceManager->GetInstance(STRING_from_string(IN_AsynNetwork ), IID_IAsynNetwork , (void **)&m_spAsynNetwork );
    }

public: // interface of asyn_message_events_impl
    DECLARE_ASYN_MESSAGE_MAP(CService)
    HRESULT OnEventNotify(uint64_t lparam1, uint64_t lparam2, IUnknown *object);
    HRESULT OnIomsgNotify(uint64_t lparam1, uint64_t lparam2, IAsynIoOperation *lpAsynIoOperation);
    HRESULT OnQueryResult(uint64_t lparam1, uint64_t lparam2, IKeyvalSetter **ppKeyval);

public:
    bool Start()
    {
        m_spInstanceManager->NewInstance(0, TC_Iocp, IID_IAsynFrameThread, (void **)&m_spAsynFrameThread);
        CreateAsynFrame(m_spAsynFrameThread, 0, &m_spAsynFrame);

        //设置全局发送/接收速度: IAsynNetwork, B/s
        CComPtr<ISpeedController> spGlobalSpeedController[2];
        CComPtr<IObjectHolder   > spObjectHolder;
        m_spAsynNetwork->QueryInterface(IID_IObjectHolder, (void **)&spObjectHolder);
        spObjectHolder->Get(Io_recv, 0, IID_ISpeedController, (void **)&spGlobalSpeedController[Io_recv]);
        spObjectHolder->Get(Io_send, 0, IID_ISpeedController, (void **)&spGlobalSpeedController[Io_send]);
        HRESULT r0 = spGlobalSpeedController[Io_recv]->SetMaxSpeed(m_setsfile.get_long("globals", "max_recvspeed", -1));
        HRESULT r1 = spGlobalSpeedController[Io_send]->SetMaxSpeed(m_setsfile.get_long("globals", "max_sendspeed", -1));

        if( m_setsfile.is_exist("ssl", "cert"))
        {// for ssl
            const std::string &file = m_setsfile.get_string("ssl", "cert");
            FILE *f = 0; errno_t hr = fopen_s(&f, file.c_str(), "rb");
            if( f )
            {
                BYTE temp[4096];
                int  size = fread(temp, 1, sizeof(temp), f);
                fclose(f);
                if( size > 0 )
                {
                    m_cert_p12.assign((char*)temp, size);
                    m_password = m_setsfile.get_string("ssl", "password");
                }
            }
            else
            {
                printf("open cert.p12[%s], error: %d\n", file.c_str(), (int)hr);
            }
        }

        CComPtr<IThreadPool> threadpool; threadpool.Attach(asynsdk::CreateThreadPool(m_spInstanceManager, "iosthreadpool?t=1&size=4", PT_FixedThreadpool));

        for(std::set<std::string>::iterator it = m_setsfile.m_sections.begin();
            it != m_setsfile.m_sections.end(); ++ it)
        {
            const std::string &csection = *it;
            if( csection != "forward.tcp" &&
                csection != "forward.udp") continue;

            if(!m_setsfile.get_bool(csection, "enabled", true)) continue;

            const std::string &protocol = csection.substr(csection.find('.') + 1);
            const std::string &af = m_setsfile.get_string(csection, "af", "ipv4");
        
            if( protocol == "udp")
            {
                std::string url = m_setsfile.get_string(csection, "url", "udp://*:0/?timeout=60");
                PORT udpport = (PORT)m_setsfile.get_long(csection, "udp_port", 0);
                {
                    CComPtr<IAsynUdpSocket> spAsynUdpSocket;
                    m_spAsynNetwork->CreateAsynUdpSocket(&spAsynUdpSocket);
            
                    HRESULT s = spAsynUdpSocket->Open(m_spAsynFrameThread, af == "ipv4" ? 2 : 23/*AF_INET:AF_INET6*/, SOCK_DGRAM, IPPROTO_UDP);
                    HRESULT t = spAsynUdpSocket->Bind(STRING_EX::null, udpport, 0, NULL); //同步bind
                    if( t != S_OK )
                    {
                        printf("bind udp://*:%d[%s.%-5s], error: %d\n", udpport, af.c_str(), protocol.c_str(), t);
                        continue;
                    }
                    if( udpport == 0 ) spAsynUdpSocket->GetSockAddress(0, 0, &udpport, 0);

                    printf("listen udp://*:%d[%s.%-5s] -> %s\n", udpport, af.c_str(), protocol.c_str(), url.c_str());

                    CComPtr<IAsynIoOperation> spAsynIoOperation; m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, 0, 0, IID_IAsynIoOperation, (void **)&spAsynIoOperation);
                    spAsynIoOperation->SetOpParam1(0); //mark is forword
                    m_spAsynNetAgent->Connect(spAsynUdpSocket, STRING_from_string("forward " + url), spAsynIoOperation, 0);
                }
            }
            else
            {
                std::string url = m_setsfile.get_string(csection, "url", "tcp://*:0");
                PORT tcpport = (PORT)m_setsfile.get_long(csection, "tcp_port", 0);
                {
                    CComPtr<IAsynTcpSocketListener> spAsynTcpSocketListener;
                    m_spAsynNetwork->CreateAsynTcpSocketListener(0, &spAsynTcpSocketListener);
                    
                    HRESULT s = spAsynTcpSocketListener->Open(m_spAsynFrameThread, af == "ipv4" ? 2 : 23/*AF_INET:AF_INET6*/, SOCK_STREAM, IPPROTO_TCP);
                    HRESULT t = spAsynTcpSocketListener->Bind(STRING_EX::null, tcpport, 0, NULL); //同步bind
                    if( t != S_OK )
                    {
                        printf("bind tcp://*:%d[%s.%-5s], error: %d\n", tcpport, af.c_str(), protocol.c_str(), t);
                        continue;
                    }
                    if( tcpport == 0 ) spAsynTcpSocketListener->GetSockAddress(0, 0, &tcpport, 0);
                    spAsynTcpSocketListener->Set(DT_SetThreadpool, 0, threadpool); //设置接入线程池
            
                    printf("listen tcp://*:%d[%s.%-5s] -> %s\n", tcpport, af.c_str(), protocol.c_str(), url.c_str());

                    CComPtr<IAsynIoOperation> spAsynIoOperation; m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, 0, 0, IID_IAsynIoOperation, (void **)&spAsynIoOperation);
                    spAsynIoOperation->SetOpParam1(0); //mark is forword
                    m_spAsynNetAgent->Connect(spAsynTcpSocketListener, STRING_from_string("forward " + url), spAsynIoOperation, 0);
               }

                PORT sslport = (PORT)m_setsfile.get_long(csection, "ssl_port", 0);
                if(!m_cert_p12.empty() &&
                    sslport )
                {
                    CComPtr<IAsynTcpSocketListener> spAsynTcpSocketListener;
                    m_spAsynNetwork->CreateAsynTcpSocketListener(0, &spAsynTcpSocketListener);
                    HRESULT s = spAsynTcpSocketListener->Open(m_spAsynFrameThread, af == "ipv4" ? 2 : 23/*AF_INET:AF_INET6*/, SOCK_STREAM, IPPROTO_TCP);
                    HRESULT t = spAsynTcpSocketListener->Bind(STRING_EX::null, sslport, 0, NULL); //同步bind
                    if( t != S_OK )
                    {
                        printf("bind tcp://*:%d[%s.%-5s], error: %d\n", sslport, af.c_str(), protocol.c_str(), t);
                        continue;
                    }
                    if( sslport == 0 ) spAsynTcpSocketListener->GetSockAddress(0, 0, &sslport, 0);
                    spAsynTcpSocketListener->Set(DT_SetThreadpool, 0, threadpool); //设置接入线程池

                    url += "/?algo=" + m_setsfile.get_string("ssl", "algo", "tls/1.0");
                    printf("listen tcp://*:%d[%s.%-5s] -> %s\n", sslport, af.c_str(), protocol.c_str(), url.c_str());

                    CComPtr<IAsynIoOperation> spAsynIoOperation; m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, 0, 0, IID_IAsynIoOperation, (void **)&spAsynIoOperation);
                    spAsynIoOperation->SetOpParam1(0); //mark is forword
                    m_spAsynNetAgent->Connect(spAsynTcpSocketListener, STRING_from_string("forward " + url), spAsynIoOperation, 0);
                }
            }
        }

        for(std::set<std::string>::iterator it = m_setsfile.m_sections.begin();
            it != m_setsfile.m_sections.end(); ++ it)
        {
            const std::string &csection = *it;
            if( csection != "proxy.ftp"   &&
                csection != "proxy.http"  &&
                csection != "proxy.socks" ) continue;

            if(!m_setsfile.get_bool(csection, "enabled", true)) continue;
 
            const std::string &protocol = csection.substr(csection.find('.') + 1);
            const std::string &af = m_setsfile.get_string(csection, "af", "ipv4");
        
            PORT tcpport = (PORT)m_setsfile.get_long(csection, "tcp_port", 0);
            {// tcp
                CComPtr<IAsynTcpSocketListener> spAsynTcpSocketListener;
                m_spAsynNetwork->CreateAsynTcpSocketListener(0, &spAsynTcpSocketListener);
                
                HRESULT s = spAsynTcpSocketListener->Open(m_spAsynFrameThread, af == "ipv4" ? 2 : 23/*AF_INET:AF_INET6*/, SOCK_STREAM, IPPROTO_TCP);
                HRESULT t = spAsynTcpSocketListener->Bind(STRING_EX::null, tcpport, 0, NULL); //同步bind
                if( t != S_OK )
                {
                    printf("bind tcp://*:%d[%s.%-5s], error: %d\n", tcpport, af.c_str(), protocol.c_str(), t);
                    continue;
                }
                if( tcpport == 0 ) spAsynTcpSocketListener->GetSockAddress(0, 0, &tcpport, 0);
                spAsynTcpSocketListener->Set(DT_SetThreadpool, 0, threadpool); //设置接入线程池

                m_arPort2ProtocolAsynTcpSocketListeners[tcpport] = std::make_pair(protocol, spAsynTcpSocketListener);
                printf("listen tcp://*:%d[%s.%-5s]\n", tcpport, af.c_str(), protocol.c_str());
            }

            PORT sslport = (PORT)m_setsfile.get_long(csection, "ssl_port", 0);
            if(!m_cert_p12.empty() &&
                sslport )
            {// ssl
                CComPtr<IAsynTcpSocketListener> spAsynTcpSocketListener;

                CComPtr<IAsynTcpSocketListener> spAsynInnSocketListener;
                m_spAsynNetwork->CreateAsynTcpSocketListener(0, &spAsynInnSocketListener);

                CComPtr<IAsynRawSocket        > spAsynPtlSocket;
                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ssl"), spAsynInnSocketListener, 0, STRING_from_string( m_setsfile.get_string("ssl", "algo", "tls/1.0")), &spAsynPtlSocket);
                if( spAsynPtlSocket == NULL )
                {
                    printf("can't load plugin: ssl\n");
                    continue;
                }
                else
                {
                    spAsynPtlSocket->QueryInterface(IID_IAsynTcpSocketListener, (void**)&spAsynTcpSocketListener);
                }

                HRESULT s = spAsynTcpSocketListener->Open(m_spAsynFrameThread, af == "ipv4" ? 2 : 23/*AF_INET:AF_INET6*/, SOCK_STREAM, IPPROTO_TCP);
                HRESULT t = spAsynTcpSocketListener->Bind(STRING_EX::null, sslport, 0, NULL); //同步bind
                if( t != S_OK )
                {
                    printf("bind ssl://*:%d[%s.%-5s], error: %d\n", sslport, af.c_str(), protocol.c_str(), t);
                    continue;
                }
                spAsynTcpSocketListener->Set(DT_SetThreadpool, 0, threadpool); //设置接入线程池

                m_arPort2ProtocolAsynTcpSocketListeners[sslport] = std::make_pair(protocol, spAsynTcpSocketListener);
                printf("listen ssl://*:%d[%s.%-5s]\n", sslport, af.c_str(), protocol.c_str());
            }
        }

        for(std::map<PORT, std::pair<std::string, CComPtr<IAsynTcpSocketListener> > >::iterator it = m_arPort2ProtocolAsynTcpSocketListeners.begin(); it != m_arPort2ProtocolAsynTcpSocketListeners.end(); ++ it)
        {
            for(int c = 0; c < 2; ++ c)
            {
                CComPtr<IAsynIoOperation> spAsynIoOperation; m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, 0, 0, IID_IAsynIoOperation, (void **)&spAsynIoOperation);
                spAsynIoOperation->SetOpParam1(it->first);
                it->second.second->Accept(spAsynIoOperation);
            }
        }
        return true;
    }

    void Stop()
    {
        asyn_message_events_impl::Stop(m_spAsynFrame);
        m_spAsynFrame = NULL;
    }

protected:
    CComPtr<InstancesManager> m_spInstanceManager;
    CComPtr<IAsynFrameThread> m_spAsynFrameThread;
    CComPtr<IAsynFrame      > m_spAsynFrame;
    CComPtr<IAsynNetwork    > m_spAsynNetwork;
    CComPtr<IAsynNetAgent   > m_spAsynNetAgent;

    setting &m_setsfile;

    std::string m_cert_p12;
    std::string m_password;

    std::map<PORT, std::pair<std::string, CComPtr<IAsynTcpSocketListener> > > m_arPort2ProtocolAsynTcpSocketListeners;
    std::map<PORT, CComPtr<IAsynTcpSocketListener> > m_arPort2AsynTcpSocketListeners;
    std::map<uint64_t,   std::unique_ptr<CSession> > m_arSock2AgentSessions;
    std::list<std::unique_ptr<CSession> > m_arForwordSessions;
};

#endif//__SERVICE_H__
