#ifndef ANALYZER_PROTOCOL_IMAP_IMAP_H
#define ANALYZER_PROTOCOL_IMAP_IMAP_H

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/ContentLine.h"
#include "analyzer/protocol/login/NVT.h"
#include "analyzer/protocol/mime/MIME.h"

#include <vector>
#include <string>
#include <algorithm>
#include "events.bif.h"

#undef IMAP_CMD_DEF
#define IMAP_CMD_DEF(cmd)  IMAP_CMD_##cmd,

namespace analyzer { namespace imap {

typedef enum{
#include "IMAP_cmd.def"
}IMAP_Cmd;


/*different possible state for the connection*/
typedef enum {
  IMAP_NO_AUTHENTICATED,//connection time or authentication failure
  IMAP_AUTHENTICATED, //after authentication success
  IMAP_SELECTED,//when a mailbox is selected
  IMAP_END, 

}IMAP_MasterState;


typedef struct command_uid{
  string uid;
  string cmd;
}Command_UID;

class IMAP_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	IMAP_Analyzer(Connection* conn);
	~IMAP_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{
		return new IMAP_Analyzer(conn);
		}

	static bool Available()	{ return imap_request || imap_reply || imap_data || imap_unexpected  || imap_login_success ||imap_login_failure; }


protected:

	// IMAP_Analyzer()	{}
	login::NVT_Analyzer* nvt_orig;
	login::NVT_Analyzer* nvt_resp;
	bool waitingForAuthentication;
	bool waitingForMailData;
	bool waitingForClientResponse;
	bool untaggedReplyRequired;
	bool isTls;
	bool firstCmd;	
	int masterState;
	bool mail_segment;
	std::size_t mail_segment_found;
	string authType;
	string mailbox;
	string lastcmd;
	string auth1;
	string auth2;
	string lastCmd;	
	static string status[];
	vector<Command_UID> cmds;//list of client commands and uids waiting for a server response

	void ProcessRequest(int length, const char * line);
	void ProcessReply(int length, const char * line);
	int ParseCmd(string cmd);
	void ImapEvent(EventHandlerPtr event, bool is_orig, const char* arg1, const char* arg2);
	void ImapDataEvent(EventHandlerPtr event, bool is_orig, bool mail_segmant_t, const char* arg1, const char* arg2);
	void ImapEventLogin(EventHandlerPtr event, const char* authType, const char* arg1, const char* arg2);
	vector <string> SplitLine(const char* input,int length, const char split);
	string getOriginalCmd(string uid, vector<Command_UID> cmdlist);
	int getIndexCommand_UID(string uid, vector<Command_UID> cmdlist);
	void NotAllowed(const char* uid, const char* cmd, const char* comment);
	bool ManageSimpleReplyEvent(string code, string arg);
	bool ManageSimpleRequestEvent(int state, string tag, string cmd, string arg);
	string ToUpper(string s);

	void BeginData(bool orig);
	void ProcessData(int length, const char* line);
	void EndData();

	mime::MIME_Mail* mail;

};

} } // namespace analyzer::* 

#endif
