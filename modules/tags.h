#ifndef ANOPE_TAGS_H
#define ANOPE_TAGS_H

struct TagEntry;

struct TagList : Serialize::Checker<std::vector<TagEntry*> >
{
	TagList(Extensible*)
		: Serialize::Checker<std::vector<TagEntry*> >("TagEntry")
	{
	}

	~TagList();
  bool SetTag(NickCore* nc, Anope::string& name, Anope::string& value);
  bool DelTag(Anope::string& name);
	void Broadcast(NickCore* nc);
  void Clear();
  JsonObject AsJsonObject();
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

bool TagList::DelTag(Anope::string& tagname)
{
		size_t listidx = this->Find(tagname);
		if (listidx > (*this)->size())
		  return false;
	
		(*this)->erase((*this)->begin() + listidx);
    return true;
}

void TagList::Clear()
{
  for (size_t idx = 0; idx < (*this)->size(); ++idx)
	{
    (*this)->erase((*this)->begin() + idx);
	}
}

bool TagList::SetTag(NickCore* nc, Anope::string& tagname, Anope::string& tagvalue)
{
  for (Anope::string::const_iterator iter = tagname.begin(); iter != tagname.end(); ++iter)
		{
			const char& chr = *iter;
			if (!isalnum(chr) && chr != '-')
			{
				// Invalid tag name
        return false;
			}
		}

		size_t listidx = this->Find(tagname);
		if (listidx < (*this)->size())
		{
			// The tag already exists; update the value.
			TagEntry* tag = (*this)->at(listidx);
			tag->value = tagvalue;
		}
		else
		{
			// The tag doesn't exist, create a new entry.
			TagEntry* tag = new TagEntry(nc);
			tag->owner = nc;
			tag->name = tagname;
			tag->value = tagvalue;
			(*this)->push_back(tag);
		}
  return true;
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

size_t TagList::Find(const Anope::string& tag_name)
{
	// It would be nice if we could use an iterator here but the serialization API
	// sadly hides the typedefs necessary to use it with old style for loops.
	for (size_t idx = 0; idx < (*this)->size(); ++idx)
	{
		TagEntry* entry = (*this)->at(idx);
		if (entry->name == tag_name)
			return idx;
	}
	return SIZE_MAX;
}

JsonObject TagList::AsJsonObject()
{
	JsonObject taglist;
	for (size_t idx = 0; idx < (*this)->size(); ++idx)
	{
		TagEntry* tag = (*this)->at(idx);
		taglist[tag->name] = tag->value;
  }
	
  return taglist;
}

#endif //ANOPE_TAGS_H
