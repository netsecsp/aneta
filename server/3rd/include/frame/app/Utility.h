///////////////////////////////////////////////////////////////////////////////
#if !defined(AFX_UTILITY_APP_H__8A503072_4124_4233_9BEF_3671D8669695__INCLUDED_)
#define AFX_UTILITY_APP_H__8A503072_4124_4233_9BEF_3671D8669695__INCLUDED_
/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 05/01/2022
http://asynframe.sf.net

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
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <string>
#include "AsynMessageEvents.h"
NAMESPACE_BEGIN(asynsdk)

///////////////////////////////////////////////////////////////////////////////
//添加到空闲的消息队列
HRESULT AppendIdleOperation(/*[in ]*/IAsynIoOperation *lpAsynIoOperation, /*[in ]*/uint32_t param2 = 0);

//投递异步消息
HRESULT PostAsynIoOperation(/*[in ]*/IAsynIoOperation *lpAsynIoOperation);
HRESULT PostAsynIoOperation(/*[in ]*/IAsynIoOperation *lpAsynIoOperation, /*[in ]*/uint32_t lErrorCode, /*[in ]*/IUnknown *pObject = 0);

//获取所绑定的异步消息
bool    TakeBindIoOperation(/*[in ]*/IAsynIoOperation *lpAsynIoOperation, /*[in ]*/bool bTaked, /*[in ]*/REFIID riid, /*[out]*/void **ppAsynIoOperation);
HRESULT PostBindIoOperation(/*[in ]*/IAsynIoOperation *lpAsynIoOperation, /*[in ]*/uint32_t lErrorCode, /*[in ]*/IUnknown *pObject = 0);

///////////////////////////////////////////////////////////////////////////////
//枚举KeyvalSetter数据
void    TravelKeyvalSetter (/*[in ]*/IKeyvalSetter *object, /*[in ]*/IAsynMessageEvents *events);

///////////////////////////////////////////////////////////////////////////////
//设置读||写速度限制器
bool    SetSpeedController (/*[in ]*/IAsynIoDevice *lpDstAsynIoDevice, /*[in ]*/uint32_t type, /*[in ]*/uint32_t level, /*[in ]*/ISpeedController *pSpeedController);

///////////////////////////////////////////////////////////////////////////////
//申请||释放内存
void   *AcquireBuffer(/*[in ]*/IMemoryPool *lpMemorypool, /*[in, out]*/uint32_t *size);
bool    ReleaseBuffer(/*[in ]*/IMemoryPool *lpMemorypool, /*[in ]*/void *addr);

///////////////////////////////////////////////////////////////////////////////
typedef enum tag_FrameThreadCore
{
    TC_Auto = 0,
    TC_Iocp,
    TC_Uapc,
    TC_Uapc_timeEvent,
} FrameThreadCore;

//建立消息循环泵: window=0表示建立异步线程循环泵，window!=0表示建立窗口线程循环泵, 注意: 允许events_ref=0, 不能用于模态对话框
void    DoMessageLoop(/*[in ]*/InstancesManager *lpInstancesManager, /*[in ]*/BOOL window, /*[in ]*/FrameThreadCore core, /*[in ]*/IAsynMessageEvents *events_ref);

//创建消息循环泵: window=0表示建立异步线程循环泵, window!=0表示建立窗口线程循环泵, 注意: 允许events_ref/ppThread=0, 可以用于模态对话框, 必须在当前线程创建/运行线程循环泵
IThreadMessagePump   *CreateThreadMessagePump(/*[in ]*/InstancesManager *lpInstancesManager, /*[in ]*/BOOL window, /*[in ]*/FrameThreadCore core, /*[in ]*/IAsynMessageEvents *events_ref, /*[out]*/IAsynFrameThread **ppThread);

///////////////////////////////////////////////////////////////////////////////
//创建数据传输器
IDataTransmit        *CreateDataTransmit(/*[in ]*/InstancesManager *lpInstancesManager, /*[in ]*/const char *name, /*[in ]*/IUnknown *pParam1, /*[in ]*/uint64_t lparam2);

///////////////////////////////////////////////////////////////////////////////
//创建命令执行器: name="cmd"表示创建系统命令执行器
IOsCommand           *CreateCommand(/*[in ]*/InstancesManager *lpInstancesManager, /*[in ]*/const char *name, /*[in ]*/IUnknown *pParam1, /*[in ]*/uint64_t lparam2);

///////////////////////////////////////////////////////////////////////////////
typedef enum tag_ThreadType
{
    TT_FrameThread = 0, //IAsynFrameThread
    TT_WorksThread,     //IThread
    TT_TwinsThread,     //IThread
} ThreadType;
//创建Os线程
IThread              *CreateThread(/*[in ]*/InstancesManager *lpInstancesManager, /*[in ]*/const char *name, /*[in ]*/ThreadType type = TT_FrameThread);

///////////////////////////////////////////////////////////////////////////////
typedef enum tag_ThreadpoolType
{
    PT_AutoxThreadpool = 0, //自动调整线程池
    PT_FixedThreadpool,     //固定大小线程池
    PT_SocksThreadpool,     //socket 线程池
    PT_EventThreadpool,     //监控事件线程池
} ThreadpoolType;
//创建线程池
IThreadPool          *CreateThreadPool(/*[in ]*/InstancesManager *lpInstancesManager, /*[in ]*/const char *name, /*[in ]*/ThreadpoolType type = PT_AutoxThreadpool);

///////////////////////////////////////////////////////////////////////////////
//获取frame 目录
std::string GetFrameFolderDirectory(/*[in ]*/InstancesManager *lpInstancesManager, /*[in ]*/bool data, /*[in ]*/uint32_t nDstCodepage = 0); //nDstCodepage=0[CP_ACP]表示ansi

///////////////////////////////////////////////////////////////////////////////
//转换编码格式
uint32_t Convert(/*[in ]*/uint32_t nSrcCodepage, /*[in ]*/const char *src, /*[in ]*/uint32_t len, /*out*/std::wstring &dst);   // XXXXX->WCHAR
uint32_t Convert(/*[in ]*/const wchar_t *src, /*[in ]*/uint32_t len, /*[in ]*/uint32_t nDstCodepage, /*out*/std::string &dst); // WCHAR->XXXXX
uint32_t Convert(/*[in ]*/uint32_t nSrcCodepage, /*[in ]*/const char *src, /*[in ]*/uint32_t len, /*[in ]*/uint32_t nDstCodepage, /*out*/std::string &dst); //XXXXX->XXXXX

NAMESPACE_END(asynsdk)

#endif // !defined(AFX_UTILITY_APP_H__8A503072_4124_4233_9BEF_3671D8669695__INCLUDED_)