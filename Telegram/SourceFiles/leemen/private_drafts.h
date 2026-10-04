#pragma once

#include <map>
#include <memory>
#include <utility>

namespace Leemen {

template <typename Key, typename Draft>
class PrivateDrafts final {
public:
	[[nodiscard]] Draft *get(const Key &key, const Draft *ordinary) {
		const auto [i, inserted] = _drafts.try_emplace(key);
		if (inserted && ordinary) {
			i->second = std::make_unique<Draft>(*ordinary);
		}
		return i->second.get();
	}

	void set(const Key &key, std::unique_ptr<Draft> draft) {
		_drafts[key] = std::move(draft);
	}

	void clear() {
		_drafts.clear();
	}

private:
	std::map<Key, std::unique_ptr<Draft>> _drafts;

};

} // namespace Leemen
