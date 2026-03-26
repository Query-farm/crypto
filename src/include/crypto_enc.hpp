#pragma once

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include <string>
#include <unordered_map>
#include <functional>

namespace duckdb
{
    void LoadCipherInternal(ExtensionLoader &loader);
    void throwOpensslError(const std::string &prefix);
};
