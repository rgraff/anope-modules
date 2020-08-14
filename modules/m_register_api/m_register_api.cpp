#include "module.h"
#include "modules/os_forbid.h"
#include "modules/httpd.h"
#include "third/json_api.h"
#include "third/m_token_auth.h"
#include "api_session.h"

ExtensibleRef<Anope::string> passcodeExt("passcode");
ExtensibleRef<bool> unconfirmedExt("UNCONFIRMED");

class APIRequest
	: public HTTPMessage
{
 public:
	typedef std::map<Anope::string, Anope::string> ParamMap;
	typedef Anope::string ip_t;

 private:
	const Anope::string client_id;
	const ip_t client_ip;
	const ip_t user_ip;

 public:
	SessionRef session;

	APIRequest(const APIRequest& other)
		: HTTPMessage(other)
		, client_id(other.client_id)
		, client_ip(other.client_ip)
		, user_ip(other.user_ip)
		, session(other.session)
	{
	}

	APIRequest(const HTTPMessage& message, const ip_t& ClientIP)
		: HTTPMessage(message)
		, client_id(GetParameter("client_id"))
		, client_ip(ClientIP)
		, user_ip(GetParameter("user_ip"))
	{
		Anope::string session_id;

		if (GetParameter("session", session_id))
			session = Session::Find(session_id, true, true);
	}

	const Anope::string& getClientId() const
	{
		return client_id;
	}

	const ip_t& getClientIp() const
	{
		return client_ip;
	}

	const ip_t& getUserIp() const
	{
		return user_ip;
	}

	bool IsValid() const
	{
		return !(client_id.empty() || client_ip.empty());
	}

	bool HasParameter(const ParamMap::key_type& name) const
	{
		return post_data.find(name) != post_data.end();
	}

	bool GetParameter(const ParamMap::key_type& name, ParamMap::mapped_type& value) const
	{
		ParamMap::const_iterator it = post_data.find(name);

		if (it == post_data.end())
			return false;

		value = it->second;

		return true;
	}

	ParamMap::mapped_type GetParameter(const ParamMap::key_type& name) const
	{
		ParamMap::mapped_type value;
		GetParameter(name, value);
		return value;
	}
};

struct RegisterData
{
	Anope::string username;
	Anope::string password;
	Anope::string ident;
	Anope::string ip;
	bool force_confirm;

	RegisterData() : force_confirm(false) {}

	static RegisterData FromMessage(APIRequest& request)
	{
		RegisterData data;
		data.username = request.GetParameter("username");
		data.ident = request.GetParameter("ident");
		data.ip = request.getUserIp();
		data.password = request.GetParameter("password");
		data.force_confirm = request.GetParameter("force_confirm") == "1";
		return data;
	}
};

class APIEndpoint;

class APILogger
	: public Log
{
 public:
	APILogger(const APIEndpoint& endpoint, const APIRequest& request);
};

class APIEndpoint
	: public JsonAPIEndpoint
{
	typedef std::set<Anope::string> RequiredParams;
	RequiredParams required_params;
	bool need_login;

 public:
	Module* creator;

	APIEndpoint(Module* Creator, const Anope::string& u)
		: JsonAPIEndpoint(u)
		, need_login(false)
		, creator(Creator)
	{
	}

	void RequireSession()
	{
		AddRequiredParam("session");
		need_login = true;
	}

	void AddRequiredParam(const Anope::string& name)
	{
		required_params.insert(name);
	}

	Anope::string GetEndpointID() const
	{
		return this->GetURL().substr(1);
	}

	bool OnRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client,
				   HTTPMessage& message, HTTPReply& reply) anope_override
	{
		APIRequest request(message, client->GetIP());

		bool logged_in = request.session && request.session->LoggedIn();

		if (need_login && !logged_in)
		{
			reply.error = HTTP_BAD_REQUEST;

			JsonObject error;
			error["id"] = "no_login";
			error["message"] = "Login required";

			JsonObject responseObj;
			responseObj["status"] = "error";
			responseObj["error"] = error;

			reply.Write(responseObj.str());
			return true;
		}

		if (!request.IsValid())
		{
			reply.error = HTTP_BAD_REQUEST;
			return true;
		}

		JsonArray missing;

		for (RequiredParams::const_iterator it = required_params.begin(); it != required_params.end(); ++it)
		{
			if (request.GetParameter(*it).empty())
				missing.push_back(*it);
		}

		if (!missing.empty())
		{
			reply.error = HTTP_BAD_REQUEST;

			JsonObject error;
			error["id"] = "missing_parameters";
			error["message"] = "Missing required request parameters";
			error["parameters"] = missing;

			JsonObject responseObj;
			responseObj["status"] = "error";
			responseObj["error"] = error;

			reply.Write(responseObj.str());
			return true;
		}

		APILogger(*this, request) << "Request received";

		return HandleRequest(provider, string, client, request, reply);
	}

	virtual bool HandleRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client,
							   APIRequest& request, HTTPReply& reply) = 0;

	virtual void DoReload(Configuration::Conf* conf)
	{
	}
};

APILogger::APILogger(const APIEndpoint& endpoint, const APIRequest& request)
	: Log(LOG_NORMAL, endpoint.GetEndpointID())
{
	*this << "API: " << category << " from " << request.getClientId()
		  << " on " << request.getClientIp();

	if (!request.getUserIp().empty())
		*this << " (user: " << request.getUserIp() << ")";

	*this << ": ";
}

class BasicAPIEndpoint
	: public APIEndpoint
{
 public:
	BasicAPIEndpoint(Module* Creator, const Anope::string& u)
		: APIEndpoint(Creator, u)
	{
	}

	bool HandleRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client, APIRequest& request,
					   HTTPReply& reply) anope_override
	{
		JsonObject responseObject, errorObject;

		if (!HandleRequest(request, responseObject, errorObject))
		{
			responseObject["error"] = errorObject;
			responseObject["status"] = "error";

			APILogger(*this, request) << "Error: " << errorObject["id"].str();
		}
		else
		{
			responseObject["status"] = "ok";
			if (request.session && request.session->Check())
				responseObject["session"] = request.session->id;
		}
		reply.Write(responseObject.str());

		return true;
	}

	virtual bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) = 0;
};

class RegistrationEndpoint
	: public BasicAPIEndpoint
{
 private:
	bool restrictopernicks;
	bool accessonreg;

	ServiceReference<ForbidService> forbidService;

	Anope::string nsregister;
	Anope::string guestnick;

 public:
	RegistrationEndpoint(Module* Creator)
		: BasicAPIEndpoint(Creator, "register")
		, restrictopernicks(true)
		, accessonreg(true)
		, forbidService("ForbidService", "forbid")
	{
		AddRequiredParam("username");
		AddRequiredParam("password");
		AddRequiredParam("user_ip");
	}

	void DoReload(Configuration::Conf* conf) anope_override
	{
		Configuration::Block* nickserv = conf->GetModule("nickserv");

		restrictopernicks = nickserv->Get<bool>("restrictopernicks");
		guestnick = nickserv->Get<const Anope::string>("guestnickprefix", "Guest");

		nsregister = conf->GetModule("ns_register")->Get<const Anope::string>("registration");

		accessonreg = conf->GetModule("ns_access")->Get<bool>("addaccessonreg");
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		RegisterData data = RegisterData::FromMessage(request);

		if (forbidService)
		{
			ForbidData* nickforbid = forbidService->FindForbid(data.username, FT_NICK);
			ForbidData* regforbid = forbidService->FindForbid(data.username, FT_REGISTER);
			if (nickforbid || regforbid)
			{
				errorObject["id"] = "forbidden_user";
				errorObject["message"] = "This nickname is forbidden from registration";
				return false;
			}
		}

		NickCoreRef nc = new NickCore(data.username);
		NickAliasRef na = new NickAlias(data.username, nc);
		Anope::Encrypt(data.password, nc->pass);

		na->last_realname = data.username;

		APILogger(*this, request) << "Account created: " << nc->display;

		FOREACH_MOD(OnNickRegister, (NULL, na, data.password));

		if (!data.ip.empty() && !data.ident.empty() && accessonreg)
			nc->AddAccess(data.ident + "@" + data.ip);

		request.session = new Session(nc);

		if (unconfirmedExt && unconfirmedExt->HasExt(nc))
		{
			responseObject["verify"] = nsregister;
			responseObject["need_verify"] = true;
		}
		else
		{
			responseObject["verify"] = "none";
			responseObject["need_verify"] = false;
		}

		return true;
	}
};

class APIIndentifyRequest
	: public IdentifyRequest
{
 private:
	HTTPReply reply;
	Reference<HTTPClient> client;
	APIRequest request;
	APIEndpoint* endpoint;

 public:
	APIIndentifyRequest(Module* o, const Anope::string& acc, const Anope::string& pass, HTTPReply& Reply,
						const Reference<HTTPClient>& Client, const APIRequest& Request, APIEndpoint* Endpoint)
		: IdentifyRequest(o, acc, pass)
		, reply(Reply)
		, client(Client)
		, request(Request)
		, endpoint(Endpoint)
	{
	}

	void OnResult(const JsonObject& obj)
	{
		reply.Write(obj.str());
		client->SendReply(&reply);
	}

	void OnSuccess() anope_override
	{
		NickAliasRef na = NickAlias::Find(GetAccount());
		if (!na)
			return OnFail();

		SessionRef session = new Session(na->nc);
		JsonObject obj;
		obj["session"] = session->id;
		obj["account"] = na->nc->display;
		obj["status"] = "ok";
		obj["verified"] = !unconfirmedExt || !unconfirmedExt->HasExt(na->nc);

		APILogger(*endpoint, request) << "Account login: " << na->nc->display;

		OnResult(obj);
	}

	void OnFail() anope_override
	{
		JsonObject obj, error;
		error["id"] = "failed_login";
		error["message"] = "Invalid login credentials";

		obj["error"] = error;
		obj["status"] = "error";

		APILogger(*endpoint, request) << "Failed account login: " << GetAccount();

		OnResult(obj);
	}
};

class AuthTokenEndpoint
  : public BasicAPIEndpoint
{
 public:
  AuthTokenEndpoint(Module* Creator)
		: BasicAPIEndpoint(Creator, "authtoken")
	{
		AddRequiredParam("username");
    AddRequiredParam("name");
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		Anope::string username = request.GetParameter("username");

    // Find our NickAlias from our username
    NickAlias* na;
    NickCore* nc;

    na = NickAlias::Find(username);
    if (na)
    {
      nc = na->nc;
    }
    else
    {
  		nc = new NickCore(username);
	  	na = new NickAlias(username, nc);
      APILogger(*this, request) << "Account created for '" << nc->display << "'";
    }

    // Get our token list
    AuthTokenList* tokens = GetTokenList(nc, true);
		if (!tokens)
		{
			errorObject["id"] = "tokens_disabled";
			errorObject["message"] = "Token authentication appears to be disabled";
			return false;
		}

    // Find or create our token
    Anope::string token_name = request.GetParameter("name");
    AuthToken* token;

    token = tokens->FindToken(token_name);
    if (!token)
    {
      token = tokens->NewToken(token_name);
      APILogger(*this, request) << "AuthToken generated for '" << username << "'";
    }
    else 
    {
      APILogger(*this, request) << "AuthToken found for '" << username << "'";
    }

    // Return token
		JsonObject tokenjson;
		tokenjson["name"] = token->GetName();
		tokenjson["token"] = token->GetToken();

		responseObject["token"] = tokenjson;

    APILogger(*this, request) << "SUCCESS: Auth token " << username;

		return true;
	}
};

struct TagEntry;

struct TagList : Serialize::Checker<std::vector<TagEntry*> >
{
	TagList(Extensible*)
		: Serialize::Checker<std::vector<TagEntry*> >("TagEntry")
	{
	}

	~TagList();
	void Broadcast(NickCore* nc);
	size_t Find(const Anope::string& name);
};

struct TagEntry : Serializable
{
	Serialize::Reference<NickCore> owner;
	Anope::string name;
	Anope::string value;

	TagEntry(Extensible*)
		: Serializable("TagEntry")
	{
	}

	~TagEntry()
	{
		TagList* entries = owner->GetExt<TagList>("taglist");
		if (entries)
		{
			std::vector<TagEntry*>::iterator it = std::find((*entries)->begin(), (*entries)->end(), this);
			if (it != (*entries)->end())
				(*entries)->erase(it);
		}
	}

	void Serialize(Serialize::Data& sd) const anope_override
	{
		if (!this->owner)
			return;

		sd["owner"] << this->owner->display;
		sd["name"] << this->name;
		sd["value"] << this->value;
	}

	static Serializable* Unserialize(Serializable* obj, Serialize::Data& sd)
	{
		Anope::string sowner;
		sd["owner"] >> sowner;
		NickCore* nc = NickCore::Find(sowner);
		if (!nc)
			return NULL;

		TagEntry* tag;
		if (obj)
			tag = anope_dynamic_static_cast<TagEntry*>(obj);
		else
		{
			tag = new TagEntry(nc);
			tag->owner = nc;
		}

		sd["name"] >> tag->name;
		sd["value"] >> tag->value;

		if (!obj)
		{
			TagList* entries = nc->Require<TagList>("taglist");
			(*entries)->push_back(tag);
		}

		return tag;
	}
};

TagList::~TagList()
{
	for (unsigned i = 0; i < (*this)->size(); ++i)
		delete (*this)->at(i);
}

void TagList::Broadcast(NickCore* nc)
{
	if (nc->users.empty())
		return;

	Anope::string encodedtags;
	for (size_t idx = 0; idx < (*this)->size(); ++idx)
	{
		if (idx > 0)
			encodedtags.push_back(' ');

		TagEntry* tag = (*this)->at(idx);
		encodedtags.append(tag->name).push_back(' ');
		for (Anope::string::const_iterator siter = tag->value.begin(); siter != tag->value.end(); ++siter)
		{
			switch (*siter)
			{
				case ';':
					encodedtags.append("\\:");
					break;
				case ' ':
					encodedtags.append("\\s");
					break;
				case '\\':
					encodedtags.append("\\s");
					break;
				case '\r':
					encodedtags.append("\\r");
					break;
				case '\n':
					encodedtags.append("\\n");
					break;
				default:
					encodedtags.append(*siter);
					break;
			}
		}
	}

	for (std::list<User*>::const_iterator it = nc->users.begin(); it != nc->users.end(); ++it)
		UplinkSocket::Message(Me) << "METADATA " << (*it)->GetUID() << " custom-tags :" << encodedtags;
}

size_t TagList::Find(const Anope::string& name)
{
	// It would be nice if we could use an iterator here but the serialization API
	// sadly hides the typedefs necessary to use it with old style for loops.
	for (size_t idx = 0; idx < (*this)->size(); ++idx)
	{
		TagEntry* entry = (*this)->at(idx);
		if (entry->name == name)
			return idx;
	}
	return SIZE_MAX;
}

class AddTagEndpoint
	: public BasicAPIEndpoint
{
 public:
	AddTagEndpoint(Module* Creator)
		: BasicAPIEndpoint(Creator, "user/tags/add")
	{
		RequireSession();
		AddRequiredParam("name");
		AddRequiredParam("value");
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		Anope::string tagname = request.GetParameter("name");
		for (Anope::string::const_iterator iter = tagname.begin(); iter != tagname.end(); ++iter)
		{
			const char& chr = *iter;
			if (!isalnum(chr) && chr != '-')
			{
				// We can't delete a non-existent tag.
				errorObject["id"] = "invalid_tag_key";
				errorObject["message"] = "Tag key contains an invalid character.";	
				return false;
			}
		}

		NickCore* nc = request.session->Account();
		TagList* list = nc->Require<TagList>("taglist");

		Anope::string tagvalue = request.GetParameter("value");	
		size_t listidx = list->Find(tagname);
		if (listidx < (*list)->size())
		{
			// The tag already exists; update the value.
			TagEntry* tag = (*list)->at(listidx);
			tag->value = tagvalue;
		}
		else
		{
			// The tag doesn't exist, create a new entry.
			TagEntry* tag = new TagEntry(nc);
			tag->owner = nc;
			tag->name = tagname;
			tag->value = tagvalue;
			(*list)->push_back(tag);
		}

		list->Broadcast(nc);
		return true;
	}
};

class DeleteTagEndpoint
	: public BasicAPIEndpoint
{
 public:
	DeleteTagEndpoint(Module* Creator)
		: BasicAPIEndpoint(Creator, "user/tags/delete")
	{
		RequireSession();
		AddRequiredParam("name");
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		NickCore* nc = request.session->Account();
		TagList* list = nc->Require<TagList>("taglist");

		size_t listidx = list->Find(request.GetParameter("name"));
		if (listidx > (*list)->size())
		{
			// We can't delete a non-existent tag.
			errorObject["id"] = "no_tag";
			errorObject["message"] = "No matching tag found.";	
			return false;
		}
	
		(*list)->erase((*list)->begin() + listidx);
		list->Broadcast(nc);
		return true;
	}
};

class ListTagsEndpoint
	: public BasicAPIEndpoint
{
 public:
	ListTagsEndpoint(Module* Creator)
		: BasicAPIEndpoint(Creator, "user/tags/list")
	{
		RequireSession();
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		NickCore* nc = request.session->Account();
		TagList* list = nc->Require<TagList>("taglist");

		JsonObject taglist;
		for (size_t idx = 0; idx < (*list)->size(); ++idx)
		{
			TagEntry* tag = (*list)->at(idx);
			taglist[tag->name] = tag->value;
		}
		responseObject["tags"] = taglist;
		return true;
	}
};

class RegisterApiModule
	: public Module
{
	ServiceReference<HTTPProvider> httpd;
	Serialize::Type session_type;

	RegistrationEndpoint reg;

	ExtensibleItem<TagList> taglist;
	Serialize::Type tagentry_type;
	AddTagEndpoint addtag;
	DeleteTagEndpoint deltag;
	ListTagsEndpoint listtags;

  AuthTokenEndpoint authtoken;

	typedef std::vector<APIEndpoint*> PageList;
	PageList pages;

 public:
	RegisterApiModule(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
		, session_type(SESSION_TYPE, Session::Unserialize)
		, reg(this)
		, taglist(this, "taglist")
		, tagentry_type("TagEntry", TagEntry::Unserialize)
		, addtag(this)
		, deltag(this)
		, listtags(this)
    , authtoken(this)
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.2");

		pages.push_back(&reg);
		pages.push_back(&addtag);
		pages.push_back(&deltag);
		pages.push_back(&listtags);
    pages.push_back(&authtoken);
	}

	void RegisterPages()
	{
		if (!httpd)
			return;

		for (PageList::iterator it = pages.begin(); it != pages.end(); ++it)
			httpd->RegisterPage(*it);
	}

	void UnregisterPages()
	{
		if (!httpd)
			return;

		for (PageList::iterator it = pages.begin(); it != pages.end(); ++it)
			httpd->UnregisterPage(*it);
	}

	~RegisterApiModule() anope_override
	{
		UnregisterPages();
	}

	void OnUserLogin(User* u) anope_override
	{
		TagList* list = u->Account()->GetExt<TagList>("taglist");
		if (list)
			list->Broadcast(u->Account());
	}

	void OnReload(Configuration::Conf* conf) anope_override
	{
		Configuration::Block* block = conf->GetModule(this);
		UnregisterPages();

		const Anope::string provider = block->Get<const Anope::string>("server", "httpd/main");
		this->httpd = ServiceReference<HTTPProvider>("HTTPProvider", provider);
		if (!httpd)
			throw ConfigException("Unable to find http reference, is m_httpd loaded?");

		RegisterPages();

		for (PageList::iterator it = pages.begin(); it != pages.end(); ++it)
			(*it)->DoReload(conf);
	}
};

MODULE_INIT(RegisterApiModule)
