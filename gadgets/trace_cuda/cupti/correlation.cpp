#include "correlation.h"
#include <cstddef>
#include <stdint.h>
#include <unordered_set>
#include <mutex>

class Correlator{
public:
  void insert(uint32_t correlation_id){
    std::lock_guard<std::mutex> lock(mutex_);
    set_.insert(correlation_id);
  }

  bool check_and_remove(uint32_t correlation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = set_.find(correlation_id);
    if (it != set_.end()) {
        set_.erase(it);
        return true;
    }
    return false;
  }

  size_t size() const{
    std::lock_guard<std::mutex> lock(mutex_);
    return set_.size();
  }
private:
  std::unordered_set<uint32_t> set_;
  mutable std::mutex mutex_;
};

extern "C" {

CorrelatorHandle correlator_create(void) {
    return new Correlator();
}

void correlator_destroy(CorrelatorHandle filter) {
    if (filter) {
        delete static_cast<Correlator*>(filter);
    }
}

void correlator_insert(CorrelatorHandle filter,
                               uint32_t correlation_id) {
    if (filter) {
        static_cast<Correlator*>(filter)->insert(correlation_id);
    }
}

bool correlator_check_and_remove(CorrelatorHandle filter,
                                         uint32_t correlation_id) {
    if (filter) {
        return static_cast<Correlator*>(filter)
            ->check_and_remove(correlation_id);
    }
    return false;
}

size_t correlator_size(CorrelatorHandle filter) {
    if (filter) {
        return static_cast<Correlator*>(filter)->size();
    }
    return 0;
}

}
