package com.southwind.service;

import com.southwind.entity.Account;

public interface AccountService {
    public Account findByUsername(String username);
}
