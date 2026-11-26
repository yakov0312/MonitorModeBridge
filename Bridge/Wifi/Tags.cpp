#include "Tags.h"

#include <algorithm>
#include <stdexcept>

namespace Wifi
{

static constexpr size_t NPOS = static_cast<size_t>(-1);

bool Tag::isVendor(const std::array<uint8_t, 3>& oui, const uint8_t type) const
{
	return is(TagNumber::VendorSpecific) && data.size() >= 4 &&
		std::equal(oui.begin(), oui.end(), data.begin()) && data[3] == type;
}

Tags Tags::parse(const std::span<const uint8_t> data)
{
	// Walk the headers to find where the last complete tag ends, then copy
	// that prefix in one go
	size_t end = 0;
	while (data.size() - end >= TAG_HEADER_LENGTH && data.size() - end - TAG_HEADER_LENGTH >= data[end + 1])
		end += TAG_HEADER_LENGTH + data[end + 1];

	Tags tags;
	tags.m_raw.assign(data.begin(), data.begin() + static_cast<long>(end));
	tags.m_complete = end == data.size();
	return tags;
}

void Tags::add(const uint8_t number, const std::span<const uint8_t> data)
{
	if (data.size() > MAX_TAG_LENGTH)
		throw std::invalid_argument("Tag data is longer than 255 bytes");
	m_raw.push_back(number);
	m_raw.push_back(static_cast<uint8_t>(data.size()));
	m_raw.insert(m_raw.end(), data.begin(), data.end());
}

void Tags::add(const TagNumber number, const std::string_view text)
{
	add(number, std::span(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

void Tags::set(const TagNumber number, const std::span<const uint8_t> data)
{
	if (data.size() > MAX_TAG_LENGTH)
		throw std::invalid_argument("Tag data is longer than 255 bytes");

	const size_t offset = offsetOf(static_cast<uint8_t>(number));
	if (offset == NPOS)
	{
		add(number, data);
		return;
	}

	// Resize the old body to the new length, then overwrite it
	const auto body = m_raw.begin() + static_cast<long>(offset + TAG_HEADER_LENGTH);
	const size_t oldLength = m_raw[offset + 1];
	if (data.size() > oldLength)
		m_raw.insert(body + static_cast<long>(oldLength), data.size() - oldLength, 0);
	else
		m_raw.erase(body + static_cast<long>(data.size()), body + static_cast<long>(oldLength));
	m_raw[offset + 1] = static_cast<uint8_t>(data.size());
	std::ranges::copy(data, m_raw.begin() + static_cast<long>(offset + TAG_HEADER_LENGTH));
}

void Tags::set(const TagNumber number, const std::string_view text)
{
	set(number, std::span(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

size_t Tags::remove(const TagNumber number)
{
	// Compact in place: keep every tag that is not `number`
	size_t read = 0;
	size_t write = 0;
	size_t removed = 0;
	while (read < m_raw.size())
	{
		const size_t length = TAG_HEADER_LENGTH + m_raw[read + 1];
		if (m_raw[read] == static_cast<uint8_t>(number))
			removed++;
		else
		{
			std::copy_n(m_raw.begin() + static_cast<long>(read), length, m_raw.begin() + static_cast<long>(write));
			write += length;
		}
		read += length;
	}
	m_raw.resize(write);
	return removed;
}

size_t Tags::offsetOf(const uint8_t number) const
{
	for (size_t pos = 0; pos < m_raw.size(); pos += TAG_HEADER_LENGTH + m_raw[pos + 1])
		if (m_raw[pos] == number)
			return pos;
	return NPOS;
}

std::optional<Tag> Tags::find(const uint8_t number) const
{
	for (const Tag tag : *this)
		if (tag.number == number)
			return tag;
	return std::nullopt;
}

std::optional<Tag> Tags::findVendor(const std::array<uint8_t, 3>& oui, const uint8_t type) const
{
	for (const Tag tag : *this)
		if (tag.isVendor(oui, type))
			return tag;
	return std::nullopt;
}

std::optional<Tag> Tags::findExtension(const TagExtension extension) const
{
	for (const Tag tag : *this)
		if (tag.is(TagNumber::ElementExtension) && !tag.data.empty() &&
			tag.data[0] == static_cast<uint8_t>(extension))
			return tag;
	return std::nullopt;
}

size_t Tags::count(const TagNumber number) const
{
	size_t n = 0;
	for (const Tag tag : *this)
		n += tag.is(number);
	return n;
}

size_t Tags::size() const
{
	return static_cast<size_t>(std::distance(begin(), end()));
}

} // namespace Wifi
