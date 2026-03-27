#include "correlation.h"
#include <cstddef>
#include <cstdint>
#include <stdint.h>
#include <sys/types.h>
#include <unordered_map>
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

class GraphCorrelatorEnter{
public:
  uint8_t state[2];
  bool seen;
  uint32_t enter_cycle;

  GraphCorrelatorEnter(uint32_t c)
    : state{GRAPH_UNINITIALIZED, GRAPH_UNINITIALIZED}
    , seen(false)
    , enter_cycle(c) {}
};


class GraphMap{
public:
  GraphMap() : current_cycle(0){}
  void insert(uint32_t cid){
    std::lock_guard<std::mutex> lock(mutex_);
    map_.emplace(cid,GraphCorrelatorEnter(current_cycle));
  }
  void cycle_start(uint32_t cycle){
    std::lock_guard<std::mutex> lock(mutex_);
    current_cycle = cycle;
    uint32_t slot = cycle %2;
    for(auto& pair: map_){
      pair.second.state[slot] = GRAPH_CYCLE_CLEARED;
    }
  }
  bool mark_seen_cycle(uint32_t cycle, uint32_t cid){
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(cid);
    if (it != map_.end()){
      uint32_t slot = cycle % 2;
      it->second.state[slot] = GRAPH_KERNEL_SEEN;
      it->second.seen = true;
      return true;
    }
    return false;
  }
  size_t size(){
    std::lock_guard<std::mutex> lock(mutex_);
    return map_.size();
  }

  void finish_cycle(){
    std::lock_guard<std::mutex> lock(mutex_);
    size_t remove = 0;
    size_t remove_fallback = 0;
    for(auto it = map_.begin();it != map_.end();){
      bool should_remove = false;
      bool is_fallback = false;
      if(it->second.state[0] == GRAPH_CYCLE_CLEARED && it->second.state[1] == GRAPH_CYCLE_CLEARED){
        if(it->second.seen){
          should_remove = true;
          remove++;
        }
        else if((current_cycle - it->second.enter_cycle)>100){
          should_remove = true;
          is_fallback = true;
          remove_fallback ++;
        }
      }
      

      if(should_remove){
        it = map_.erase(it);
      }
      else {
        ++it;
      }
      
    }
  }

  void get_stat(size_t& size, size_t& oldest_age)const{
    std::lock_guard<std::mutex> lock(mutex_);
    size = map_.size();
    oldest_age = 0;
    for(const auto& pair: map_){
      uint32_t age = current_cycle - pair.second.enter_cycle;
      if(age > oldest_age){
        oldest_age = age;
      }
    }
  }
private:
  std::unordered_map<uint32_t, GraphCorrelatorEnter> map_;
  uint32_t current_cycle;
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

GraphMapHandle graph_map_create(void){
  return new GraphMap();
}

void graph_map_destroy(GraphMapHandle map){
  if(map){
    delete static_cast<GraphMap*>(map);
  }
}

void graph_map_insert(GraphMapHandle map, uint32_t cid){
  if(map){
    static_cast<GraphMap*>(map)->insert(cid);
  }
}
void graph_map_cycle_start(GraphMapHandle map, uint32_t cycle){
  if (map) {
    static_cast<GraphMap*>(map)->cycle_start(cycle);
  }
}
bool graph_map_mark_seen_cycle(GraphMapHandle map,uint32_t cid, uint32_t cycle){
  if(map){
    return static_cast<GraphMap*>(map)->mark_seen_cycle(cycle, cid);
  }
  return false;
}

void graph_map_finish_cycle(GraphMapHandle map){
  if (map) {
    static_cast<GraphMap*>(map)->finish_cycle();
  }
}
void graph_map_get_stat(GraphMapHandle map, size_t* size, size_t* old_age){
  if (map){
    static_cast<GraphMap*>(map)->get_stat(*size, *old_age);
  }
}
size_t graph_map_size(GraphMapHandle map){
  if(map){
    return static_cast<GraphMap*>(map)->size();
  }
  return 0;
}

}
