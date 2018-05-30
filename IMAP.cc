/* Implementation of an imap analyzer (RFC 3501)*/


#include "bro-config.h"

// #include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include "NetVar.h"
#include "IMAP.h"
#include "analyzer/protocol/login/NVT.h"
#include "Event.h"
#include "Reporter.h"
#include <iostream>
#include <ctype.h>
#include <vector>
#include <string>

#include "events.bif.h"

using namespace analyzer::imap;

#undef IMAP_CMD_DEF
#define IMAP_CMD_DEF(cmd)      #cmd,

static const char *imap_cmd_word[] = {
#include "IMAP_cmd.def"
};

#define IMAP_CMD_WORD(code) ((code>=0) ? imap_cmd_word[code]:"(UNKNOW)")

static string status[] = {"MESSAGES", "RECENT", "UIDNEXT", "UIDVALIDITY", "UNSEEN"};

IMAP_Analyzer::IMAP_Analyzer(Connection *conn)
        : tcp::TCP_ApplicationAnalyzer("IMAP", conn) {
    masterState = IMAP_NO_AUTHENTICATED;
    waitingForAuthentication = false;
    waitingForMailData = false;
    waitingForClientResponse = false;
    untaggedReplyRequired = false;
    isTls = false;
    firstCmd = true;
    authType = "";
    auth1 = "";
    auth2 = "";
    lastcmd = "";

    mail = 0;
    mail_segment = false;
    mail_segment_found = 0;

    AddSupportAnalyzer(new login::NVT_Analyzer(conn, true));
    AddSupportAnalyzer(new login::NVT_Analyzer(conn, false));

}

IMAP_Analyzer::~IMAP_Analyzer() {
}

void IMAP_Analyzer::Done() {
    tcp::TCP_ApplicationAnalyzer::Done();
    if (mail) {
        EndData();
    }
}

void IMAP_Analyzer::DeliverStream(int length, const u_char *data, bool orig) {
    tcp::TCP_ApplicationAnalyzer::DeliverStream(length, data, orig);

//  if ( (orig && ! imap_request) || (! orig && ! imap_reply) || (length ==0) || isTls)
//    return;
    if ((length == 0) || isTls) {
        return;
    }

    const char *line = (const char *) data;

    if (orig)
        ProcessRequest(length, line);
    else
        ProcessReply(length, line);
}

/* Launch an event if an action was forbidden for the current state.*/
void IMAP_Analyzer::NotAllowed(const char *uid, const char *cmd, const char *comment) {
    if (int position = getIndexCommand_UID(uid, cmds) >= 0)
        cmds.erase(cmds.begin() + position);

    lastcmd = "";
    ImapEvent(imap_unexpected, true, cmd, comment);
}

void IMAP_Analyzer::ProcessRequest(int length, const char *line) {

    EventHandlerPtr f = imap_request;
    vector<string> tokens;
    vector<string> auths;
    vector<string> tmp;;
    int cmd_code = -1;
    tokens = SplitLine(line, length, ' ');


    /*
      In this case the client doesn't send a new request with a new tag, but reply to the server
      wihtout using a tag.
      It is done for instance if the client is authenticating (PLAIN, CRAM, DIGEST..) or after an IDLE command.

        CLIENT  : 12 IDLE
        SERVEUR : + idling
  ->    CLIENT  : DONE
        SERVEUR : 12 OK Idle completed.

     */
    if (waitingForClientResponse == true) {
        waitingForClientResponse = false;
        if (waitingForAuthentication == true) {
            if (!(ToUpper(authType).compare("PLAIN"))) {
                auth1 = tokens[0];//If it is a plain authentication, we store the only token (which is encode_base64(login+password) into auth1
            } else if ((!(ToUpper(authType).compare("CRAM-MD5"))) || (!ToUpper(authType).compare("DIGEST-MD5"))) {
                if (tokens.size() && tokens[0].size()) {
                    if (auth1.size())
                        auth1 = auth1 + " " + tokens[0];
                    else
                        auth1 = tokens[0];
                }
            }
            return;
        } else if (!ToUpper(lastcmd).compare("IDLE")) {
            waitingForClientResponse = false;
            return;
        }
    }

    /*
      If the last command was APPEND, then the client could send data to the serveur without a tag.
      For isntance :

    $>4 append "Drafts" (\Draft)
      From: bob <bob@debian>
      X-Mozilla-Draft-Info: internal/draft; vcard=0; receipt=0; DSN=0; uuencode=0
      User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.12) Gecko/20130116 Icedove/10.0.12
      MIME-Version: 1.0
      To: test@test
      Subject: this is a test
      Content-Type: text/html; charset=ISO-8859-1
      Content-Transfer-Encoding: 7bit
      <html>
      <head>
      <meta http-equiv="content-type" content="text/html; charset=ISO-8859-1">
      </head>
      message
      </body>
      </html>

     */
    if (!ToUpper(lastcmd).compare("APPEND")) {
        ImapDataEvent(imap_data, true, false, lastcmd.c_str(), line);
        return;
    }

    if (tokens[0].size() == 0 || tokens[1].size() == 0) {
        Weird("imap_syntax_error");
        return;
    } else
        cmd_code = ParseCmd(tokens[1].c_str());

    Command_UID cuid = {tokens[0], tokens[1]};
    //if the client send severals requests without waiting for the server response, we store them into "cmds"
    cmds.push_back(cuid);
    lastcmd = ToUpper(cuid.cmd);
    /* First, if the command does not need arguments */
    if (tokens[2].size() == 0) {
        switch (cmd_code) {

            /* Possible commands from every state */

            case IMAP_CMD_CAPABILITY :
                untaggedReplyRequired = true;
                ImapEvent(f, true, tokens[1].c_str(), "");
                break;

            case IMAP_CMD_NOOP:
                ImapEvent(f, true, tokens[1].c_str(), "");
                break;

            case IMAP_CMD_LOGOUT :
                untaggedReplyRequired = true;
                ImapEvent(f, true, tokens[1].c_str(), "");
                break;

                /* Possible commands from the SELECTED state */

            case IMAP_CMD_CHECK:
                ManageSimpleRequestEvent(IMAP_SELECTED, tokens[0], tokens[1], "");
                break;

            case IMAP_CMD_CLOSE:

                if (ManageSimpleRequestEvent(IMAP_SELECTED, tokens[0], tokens[1], ""))
                    masterState = IMAP_AUTHENTICATED;
                break;

            case IMAP_CMD_EXPUNGE:
                ManageSimpleRequestEvent(IMAP_SELECTED, tokens[0], tokens[1], "");
                break;

                /* Not in rfc 3501 */
            case IMAP_CMD_NAMESPACE:
                ImapEvent(f, true, tokens[1].c_str(), "");
                break;
            case IMAP_CMD_IDLE:
                ImapEvent(f, true, tokens[1].c_str(), "");
                break;

            default:
                NotAllowed(tokens[0].c_str(), tokens[1].c_str(), "command unknown, or it needs arguments");
        }
    }
        /* Then the commands which need arguments*/
    else {
        switch (cmd_code) {

            /* Possible commands from the NO AUTHENTICATED state */

            case IMAP_CMD_LOGIN :
                authType = tokens[1];
                auths = SplitLine(tokens[2].c_str(), tokens[2].length(), ' ');
                auth1 = auths[0];
                auth2 = auths[1];
                ManageSimpleRequestEvent(IMAP_NO_AUTHENTICATED, tokens[0], tokens[1], tokens[2]);
                break;

            case IMAP_CMD_AUTHENTICATE:
                if (masterState == IMAP_NO_AUTHENTICATED) {
                    if (!(ToUpper(tokens[2]).compare("CRAM-MD5"))) {
                        authType = tokens[2];
                        waitingForAuthentication = true;
                        untaggedReplyRequired = true;
                        ImapEvent(f, true, tokens[1].c_str(), tokens[2].c_str());
                    }
                    if (!(ToUpper(tokens[2]).compare("DIGEST-MD5"))) {
                        authType = tokens[2];
                        waitingForAuthentication = true;
                        untaggedReplyRequired = true;
                        ImapEvent(f, true, tokens[1].c_str(), tokens[2].c_str());
                    }
                    if (!(ToUpper(tokens[2]).compare("PLAIN"))) {
                        authType = tokens[2];
                        waitingForAuthentication = true;
                        untaggedReplyRequired = true;
                        ImapEvent(f, true, tokens[1].c_str(), tokens[2].c_str());
                    }

                } else
                    NotAllowed(tokens[0].c_str(), tokens[1].c_str(), "the current state does not allow this action");
                break;

            case IMAP_CMD_STARTTLS:
                if (masterState == IMAP_NO_AUTHENTICATED)
                    isTls = true;
                else
                    NotAllowed(tokens[0].c_str(), tokens[1].c_str(), "the current state does not allow this action");
                break;


                /* Possible commands from the AUTHENTICATED state */

            case IMAP_CMD_SELECT:
                if (masterState == IMAP_AUTHENTICATED || masterState == IMAP_SELECTED) {
                    untaggedReplyRequired = true;
                    mailbox = tokens[2];
                    ImapEvent(imap_request, true, tokens[1].c_str(), tokens[2].c_str());
                } else
                    NotAllowed(tokens[0].c_str(), tokens[1].c_str(), "the current state does not allow this action");
                break;

            case IMAP_CMD_EXAMINE :
                if (ManageSimpleRequestEvent(IMAP_AUTHENTICATED, tokens[0], tokens[1], tokens[2])) {
                    untaggedReplyRequired = true;
                    mailbox = tokens[2];
                }
                break;

            case IMAP_CMD_CREATE:
                ManageSimpleRequestEvent(IMAP_AUTHENTICATED, tokens[0], tokens[1], tokens[2]);
                break;

            case IMAP_CMD_DELETE:
                ManageSimpleRequestEvent(IMAP_AUTHENTICATED, tokens[0], tokens[1], tokens[2]);
                break;

            case IMAP_CMD_RENAME:
                ManageSimpleRequestEvent(IMAP_AUTHENTICATED, tokens[0], tokens[1], tokens[2]);
                break;

            case IMAP_CMD_SUBSCRIBE:
                ManageSimpleRequestEvent(IMAP_AUTHENTICATED, tokens[0], tokens[1], tokens[2]);
                break;

            case IMAP_CMD_UNSUBSCRIBE:
                ManageSimpleRequestEvent(IMAP_AUTHENTICATED, tokens[0], tokens[1], tokens[2]);
                break;

            case IMAP_CMD_LIST:
                ManageSimpleRequestEvent(IMAP_AUTHENTICATED, tokens[0], tokens[1], tokens[2]);
                break;

            case IMAP_CMD_LSUB:
                ManageSimpleRequestEvent(IMAP_AUTHENTICATED, tokens[0], tokens[1], tokens[2]);
                break;

            case IMAP_CMD_STATUS:
                if ((masterState == IMAP_AUTHENTICATED) || (masterState == IMAP_SELECTED)) {
                    untaggedReplyRequired = true;
                    ImapEvent(f, true, tokens[1].c_str(), tokens[2].c_str());
                } else
                    NotAllowed(tokens[0].c_str(), tokens[1].c_str(), "the current state does not allow this action");
                break;

            case IMAP_CMD_APPEND:
                //In this case the IMAP_SELECTED state is add although not it is not excplicited into the rfc.
                //Tests show that the append command is often use with the SELECTED state.
                if ((masterState == IMAP_AUTHENTICATED) || (masterState == IMAP_SELECTED))
                    ImapEvent(f, true, tokens[1].c_str(), tokens[2].c_str());
                else
                    NotAllowed(tokens[0].c_str(), tokens[1].c_str(), "the current state does not allow this action");
                break;


                /* Possible commands from the SELECTED state */

            case IMAP_CMD_SEARCH:
                if (ManageSimpleRequestEvent(IMAP_SELECTED, tokens[0], tokens[1], tokens[2]))
                    untaggedReplyRequired = true;
                break;

            case IMAP_CMD_FETCH:
                if (ManageSimpleRequestEvent(IMAP_SELECTED, tokens[0], tokens[1], tokens[2])) {
                    untaggedReplyRequired = true;
                    waitingForMailData = true;
                }
                break;

            case IMAP_CMD_STORE:
                if (ManageSimpleRequestEvent(IMAP_SELECTED, tokens[0], tokens[1], tokens[2]))
                    untaggedReplyRequired = true;
                break;

            case IMAP_CMD_COPY:
                ManageSimpleRequestEvent(IMAP_SELECTED, tokens[0], tokens[1], tokens[2]);
                if (masterState == IMAP_SELECTED)
                    ImapEvent(f, true, tokens[1].c_str(), tokens[2].c_str());
                else
                    NotAllowed(tokens[0].c_str(), tokens[1].c_str(), "the current state does not allow this action");
                break;

            case IMAP_CMD_UID:
                if (ManageSimpleRequestEvent(IMAP_SELECTED, tokens[0], tokens[1], tokens[2]))
                    untaggedReplyRequired = true;
                tmp = SplitLine(tokens[2].c_str(), tokens[2].size(), ' ');
                if (!(ToUpper(tmp[0]).compare("FETCH"))) {
                    lastcmd = tokens[2];
                    waitingForMailData = true;
                }
                break;


                /* NOT in RFC 3501*/
            case IMAP_CMD_ENABLE:
                if (masterState == IMAP_AUTHENTICATED)
                    ImapEvent(f, true, tokens[1].c_str(), tokens[2].c_str());
                break;
            case IMAP_CMD_ID:
                ImapEvent(f, true, tokens[1].c_str(), tokens[2].c_str());
                break;

            default:
                NotAllowed(tokens[0].c_str(), tokens[1].c_str(), "the current state does not allow this action");
        }
    }
    firstCmd = false;
    ProtocolConfirmation();
}


void IMAP_Analyzer::ProcessReply(int length, const char *line) {
    const char* end_of_line = line + length;
    EventHandlerPtr f = imap_reply;
    string origCmd;
    int error_code = -1;
    vector<string> tokens = SplitLine(line, length, ' ');
    int cmd_code = -1;

    if (tokens[0][0] == '*') {
        untaggedReplyRequired = false;
        //If there are no previous command, this repsonse is unexpected.
        //If it is the first command, it is consider like cmd which establish the connection
        if ((cmds.size() == 0) && (firstCmd == false))
            NotAllowed(tokens[0].c_str(), tokens[1].c_str(), "unexpected command, may be due to a packet loss.");

        if (tokens[1].size() == 0)
            return;
        else
            mail_segment_found = tokens[2].find("FETCH (UID");
            if (mail_segment_found != std::string::npos){
                mail_segment_found = tokens[2].find("BODY");
                if (mail_segment_found != std::string::npos) {
                    mail_segment = true;
                }
            }
            cmd_code = ParseCmd(tokens[1].c_str());

        switch (cmd_code) {

            case IMAP_CMD_CAPABILITY :
                ImapEvent(f, false, tokens[1].c_str(), tokens[2].c_str());
                break;
            case IMAP_CMD_BYE:
                if (!(ToUpper(lastcmd).compare("LOGOUT")))
                    ImapEvent(f, false, tokens[1].c_str(), tokens[2].c_str());
                break;
            case IMAP_CMD_PREAUTH:
                break;
            case IMAP_CMD_OK:
                break;
            case IMAP_CMD_NO:
                break;
            case IMAP_CMD_BAD:
                break;
            case IMAP_CMD_LIST:
                break;
            case IMAP_CMD_LSUB:
                break;
            case IMAP_CMD_STATUS:
                break;
            case IMAP_CMD_EXPUNGE:
                break;
            case IMAP_CMD_SEARCH:
                break;
            case IMAP_CMD_FETCH:
                break;
            case IMAP_CMD_STORE:
                break;
            case IMAP_CMD_UID:
                break;

                /* Not in rfc 3501*/
            case IMAP_CMD_NAMESPACE:
                break;
            case IMAP_CMD_ENABLED:
                break;
            case IMAP_CMD_ID:
                break;

            default:
                return;
        }
    } else if (tokens[0][0] == '+') {
        waitingForClientResponse = true;
        if (waitingForAuthentication == true) {
            if (!(ToUpper(authType).compare("PLAIN")))
                untaggedReplyRequired = false;
            else if (!(ToUpper(authType).compare("CRAM-MD5")) || (!(ToUpper(authType).compare("DIGEST-MD5")))) {
                if (tokens.size() && tokens[1].size()) {
                    if (auth2.size())
                        auth2 = auth2 + " " + tokens[1];
                    else
                        auth2 = tokens[1];
                    untaggedReplyRequired = false;
                }
            }
        }
    } else {
        origCmd = getOriginalCmd(tokens[0], cmds);
        firstCmd = false;
        if (origCmd.size() != 0) {
            if (int position = getIndexCommand_UID(tokens[0], cmds) >= 0)
                cmds.erase(cmds.begin() + position);

            lastcmd = "";
            cmd_code = ParseCmd(origCmd.c_str());
            error_code = ParseCmd(tokens[1].c_str());

            if (tokens[2].c_str() > 0) {
                switch (cmd_code) {

                    case IMAP_CMD_CAPABILITY :
                        untaggedReplyRequired = false;
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_NOOP:
                        ImapEvent(f, true, tokens[1].c_str(), tokens[2].c_str());
                        break;

                    case IMAP_CMD_LOGOUT :
                        untaggedReplyRequired = false;
                        masterState = IMAP_NO_AUTHENTICATED;
                        ImapEvent(f, true, tokens[1].c_str(), NULL);
                        break;


                        /* Commands NO AUTHENTICATED */
                    case IMAP_CMD_LOGIN:
                        if (error_code == IMAP_CMD_OK) {
                            masterState = IMAP_AUTHENTICATED;
                            ImapEventLogin(imap_login_success, authType.c_str(), auth1.c_str(), auth2.c_str());
                        } else if (error_code == IMAP_CMD_NO || error_code == IMAP_CMD_BAD) {
                            masterState = IMAP_NO_AUTHENTICATED;
                            ImapEventLogin(imap_login_failure, authType.c_str(), auth1.c_str(), auth2.c_str());
                        } else
                            NotAllowed(tokens[0].c_str(), tokens[1].c_str(), "command unknow or syntax error");
                        break;

                    case IMAP_CMD_AUTHENTICATE:
                        if (ManageSimpleReplyEvent(tokens[1], tokens[2])) {
                            ImapEventLogin(imap_login_success, authType.c_str(), auth1.c_str(), auth2.c_str());
                            waitingForAuthentication = false;
                            masterState = IMAP_AUTHENTICATED;
                        } else
                            ImapEventLogin(imap_login_failure, authType.c_str(), auth1.c_str(), auth2.c_str());
                        break;

                    case IMAP_CMD_STARTTLS:
                        if (error_code == IMAP_CMD_OK)
                            isTls = true;
                        break;

                        /* AUTHENTICATED STATE */
                    case IMAP_CMD_SELECT:
                        if (error_code == IMAP_CMD_OK) {
                            if (untaggedReplyRequired == true)
                                Weird("content expected");
                            untaggedReplyRequired = false;
                            masterState = IMAP_SELECTED;
                            ImapEvent(f, false, "OK", tokens[2].c_str());
                        } else if (error_code == IMAP_CMD_NO || error_code == IMAP_CMD_BAD) {
                            masterState = IMAP_AUTHENTICATED;
                            ImapEvent(f, false, tokens[1].c_str(), tokens[2].c_str());
                        }
                        break;

                    case IMAP_CMD_EXAMINE:
                        if (error_code == IMAP_CMD_OK) {
                            if (untaggedReplyRequired == true)
                                Weird("content expected");

                            untaggedReplyRequired = false;
                            masterState = IMAP_SELECTED;
                            ImapEvent(f, false, "OK", tokens[2].c_str());
                        } else if (error_code == IMAP_CMD_NO || error_code == IMAP_CMD_BAD) {
                            masterState = IMAP_AUTHENTICATED;
                            ImapEvent(f, false, tokens[1].c_str(), tokens[2].c_str());
                        }
                        break;

                    case IMAP_CMD_CREATE:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        if (error_code == IMAP_CMD_OK)
                            ImapEvent(f, false, "OK", tokens[2].c_str());
                        else if (error_code == IMAP_CMD_NO || error_code == IMAP_CMD_BAD)
                            ImapEvent(f, false, tokens[1].c_str(), tokens[2].c_str());
                        break;

                    case IMAP_CMD_DELETE:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_RENAME:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_SUBSCRIBE:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_UNSUBSCRIBE:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_LIST:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_LSUB:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_STATUS:
                        if (untaggedReplyRequired == true)
                            Weird("content expected");
                        untaggedReplyRequired = false;
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_APPEND:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                        /* SLECTED STATE */
                    case IMAP_CMD_CHECK:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_CLOSE:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_EXPUNGE:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_SEARCH:
                        if (untaggedReplyRequired == true)
                            Weird("content expected");
                        untaggedReplyRequired = false;
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_FETCH:
                        waitingForMailData = false;
                        if (untaggedReplyRequired == true)
                            Weird("content expected");
                        untaggedReplyRequired = false;
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_STORE:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_COPY:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    case IMAP_CMD_UID:
                        waitingForMailData = false;

                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                        /* Not in rfc 3501*/
                    case IMAP_CMD_NAMESPACE:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;
                    case IMAP_CMD_ENABLE:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;
                    case IMAP_CMD_ID:
                        ManageSimpleReplyEvent(tokens[1], tokens[2]);
                        break;

                    default:
                        ImapEvent(f, true, tokens[1].c_str(), "command unknown");
                        break;
                }
            } else
                NotAllowed(tokens[0].c_str(), tokens[1].c_str(), "no argument given");

        }

            /*If the server send data about a mail, there are no +, * or tag, but just data about the mail :
          Exemple of a response to "UID fetch 7 .." request :

          * 7 FETCH (UID 7 RFC822.SIZE 401 BODY[] {401}
          Return-Path: <test@debian>
          X-Original-To: bob@debian
          Delivered-To: bob@debian
          Received: by debian (Postfix, from userid 1000)
          id 6421C1A4396; Tue,  2 Apr 2013 16:07:26 +0200 (CEST)
          To: bob@debian
          Subject: dovecot test
          Cc: admin@dovecot.test
          Message-Id: <20130402140726.6421C1A4396@debian>
          Date: Tue,  2 Apr 2013 16:07:26 +0200 (CEST)
          From: test@debian (test)

          So if the current line doesn't begin with '+', '*' or a tag, we test if the client is waiting for data about mail (after a fetch command for instance).
          If so, we launch a imap_data event, and the bro script will be able to build the mail.
            */
        else if (waitingForMailData) {
            if (mail_segment){
//                if (mail){
//                    EndData();
//                    BeginData(false);
//                    int data_len = end_of_line - line;
//                    ProcessData(data_len,line);
//                }else{
//                    BeginData(false);
//                    int data_len = end_of_line - line;
//                    ProcessData(data_len,line);
//                }
                ImapDataEvent(imap_data, false, true, lastcmd.c_str(), line);
                mail_segment = false;
            } else{
//                if (mail) {
//                    int data_len = end_of_line - line;
//                    ProcessData(data_len,line);
//                }else{
//                    BeginData(false);
//                    int data_len = end_of_line - line;
//                    ProcessData(data_len,line);
//
//                }
                ImapDataEvent(imap_data, false, false, lastcmd.c_str(), line);
                return;
            }

        } else
            Weird("data unexpected");

    }
}

/*
Given a command, return its enum code from the IMAP_cmd.def file.
 */

void IMAP_Analyzer::BeginData(bool orig)
{
    if (! mail) {
//    delete mail;
        mail = new mime::MIME_Mail(this, orig);
    } else{
        mail->Done();
        delete mail;
        mail = new mime::MIME_Mail(this, orig);
    }
}

void IMAP_Analyzer::EndData()
{
    if ( ! mail )
        reporter->Warning("unmatched end of data");
    else
    {
        mail->Done();
        delete mail;
        mail = 0;
    }
}

void IMAP_Analyzer::ProcessData(int length, const char* line)
{
    mail->Deliver(length, line, 1);
}

int IMAP_Analyzer::ParseCmd(string cmd) {
    if (cmd.size() == 0)
        return -1;

    for (int code = IMAP_CMD_START; code <= IMAP_CMD_END; ++code) {
        for (unsigned int i = 0; i < cmd.size(); ++i)
            cmd[i] = toupper(cmd[i]);

        if (!cmd.compare(imap_cmd_word[code]))
            return code;
    }
    return -1;
}

string IMAP_Analyzer::ToUpper(string s) {
    for (unsigned int i = 0; i < s.size(); ++i)
        s[i] = toupper(s[i]);
    return s;
}

/*
if authType ==LOGIN
arg1=login
arg2=password

if authType ==PLAIN
arg1=encoded_base64(login+password)
arg2=NULL;

if authType== (CRAM-MD5||DIGEST-MD5)
arg1= "hash" client
arg2= "hash" server

The bro script has to managed differently these 3 cases.
*/
void IMAP_Analyzer::ImapEventLogin(EventHandlerPtr event, const char *authType, const char *arg1, const char *arg2) {
    if (!event)
        return;

    val_list *vl = new val_list;
    vl->append(BuildConnVal());

    vl->append(new StringVal(authType));
    vl->append(new StringVal(arg1));
    vl->append(new StringVal(arg2));

    ConnectionEvent(event, vl);
}

void IMAP_Analyzer::ImapEvent(EventHandlerPtr event, bool is_orig, const char *arg1, const char *arg2) {
    if (!event)
        return;

    val_list *vl = new val_list;

    vl->append(BuildConnVal());

    vl->append(new Val(is_orig, TYPE_BOOL));
    if (arg1)
        vl->append(new StringVal(arg1));
    else
        vl->append(new StringVal("<empty>"));
    if (arg2)
        vl->append(new StringVal(arg2));
    else
        vl->append(new StringVal("<empty>"));

    ConnectionEvent(event, vl);
}

void IMAP_Analyzer::ImapDataEvent(EventHandlerPtr event, bool is_orig, bool mail_segment_t, const char *arg1, const char *arg2) {
    if (!event)
        return;

    val_list *vl = new val_list;

    vl->append(BuildConnVal());

    vl->append(new Val(is_orig, TYPE_BOOL));
    vl->append(new Val(mail_segment_t, TYPE_BOOL));
    if (arg1)
        vl->append(new StringVal(arg1));
    else
        vl->append(new StringVal("<empty>"));
    if (arg2)
        vl->append(new StringVal(arg2));
    else
        vl->append(new StringVal("<empty>"));

    ConnectionEvent(event, vl);
}


/*
Cut a line in 2 or 3 part.
For instance:
1)
"abcd LOGIN" return a vector of string [0]=abcd, string[1]=LOGIN
2)
"* OK LOGIN done" reutrn string[0]=*, string[1]=OK, string[2]=LOGIN done

 */
vector<string> IMAP_Analyzer::SplitLine(const char *line, int length, const char split) {

    vector<string> tokens;
    const char *end_of_line = line + length;
    const char *word1;
    const char *word2;
    int word1_len, word2_len;
    string word1s, word2s, word3s;


    line = skip_whitespace(line, end_of_line);
    get_word(length, line, word1_len, word1);

    if (word1_len == 0)
        return tokens;
    else {
        word1s = (string(line, 0, word1_len));
        tokens.push_back(word1s);
    }

    line = skip_whitespace(line + word1_len, end_of_line);
    get_word(length, line, word2_len, word2);

    if (word2_len == 0)
        return tokens;
    else {
        word2s = string(line, 0, word2_len);
        tokens.push_back(word2s);
    }

    line = skip_whitespace(line + word2_len, end_of_line);
    word3s = string(line);
    tokens.push_back(word3s);
    return tokens;
}

/*
Given an the uid of a command and a Command_UID list, it returns the name of the command.
It return NULL if the uid is not in the list.
 */
string IMAP_Analyzer::getOriginalCmd(string uid, vector<Command_UID> cmdlist) {
    if (uid.size() == 0 || cmdlist.size() == 0) {
        return string("");
    }
    for (unsigned int i = 0; i < cmdlist.size(); i++) {

        if (cmdlist[i].uid.compare(uid) == 0)
            return cmdlist[i].cmd;
    }
    return string("");
}

/*
Return the index af a command_UID if this one is into the cmdlist.
Return -1 otherwise.
 */
int IMAP_Analyzer::getIndexCommand_UID(string uid, vector<Command_UID> cmdlist) {
    if (uid.size() == 0 || cmdlist.size() == 0)
        return -1;

    for (unsigned int i = 0; i < cmdlist.size(); i++) {
        if (cmdlist[i].uid.compare(uid) == 0)
            return i;
    }
    return -1;

}

bool IMAP_Analyzer::ManageSimpleReplyEvent(string code, string arg) {
    ProtocolConfirmation();
    int error_code = ParseCmd(code.c_str());
    if (error_code == IMAP_CMD_OK) {
        ImapEvent(imap_reply, false, code.c_str(), arg.c_str());
        return true;
    } else if (error_code == IMAP_CMD_NO || error_code == IMAP_CMD_BAD)
        ImapEvent(imap_reply, false, code.c_str(), arg.c_str());
    return false;
}

bool IMAP_Analyzer::ManageSimpleRequestEvent(int state, string tag, string cmd, string arg) {
    ProtocolConfirmation();
    if (masterState == state) {
        ImapEvent(imap_request, true, cmd.c_str(), arg.c_str());
        return true;
    } else
        NotAllowed(tag.c_str(), cmd.c_str(), arg.c_str());
    return false;
}
