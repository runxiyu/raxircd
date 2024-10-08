// Services pseudoclients
//
// Written by: Test_User <hax@runxiyu.org>
//
// This is free and unencumbered software released into the public
// domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

#include <lmdb.h>
#include <stdlib.h>

#include "../config.h"
#include "hax_string.h"
#include "hax_string_utils.h"
#include "../general_network.h"
#include "../pseudoclients.h"
#include "services.h"

MDB_env *services_db_env;

MDB_dbi services_nick_to_account;
MDB_dbi services_cert_to_account;
MDB_dbi services_account_to_nicks;
MDB_dbi services_account_to_certs;
MDB_dbi services_account_to_name;

int services_pseudoclient_init(void) {
	return services_pseudoclient_post_reload();
}

int services_pseudoclient_post_reload(void) {
	size_t now;
	{
		time_t tmp = time(0);
		if (tmp < 0) {
			WRITES(2, STRING("Please check your clock.\r\n"));
			return 1;
		}

		now = (size_t)tmp;
	}

	if (!has_table_index(user_list, NICKSERV_UID)) {
		if (add_user(SID, SID, NICKSERV_UID, NICKSERV_NICK, NICKSERV_FULLNAME, NICKSERV_IDENT, NICKSERV_VHOST, NICKSERV_HOST, NICKSERV_ADDRESS, now, now, 0, 0, 0, 1, SERVICES_PSEUDOCLIENT) != 0)
			return 1;
		char exists;
		struct user_info *user = get_table_index(user_list, NICKSERV_UID, &exists).data;
		if (set_channel(SID, SERVICES_CHANNEL, now, 1, &user) != 0)
			return 1;
	}

	if (mdb_env_create(&services_db_env) != 0)
		return 1;
	if (mdb_env_set_mapsize(services_db_env, SERVICES_DB_MAX_SIZE) != 0)
		return 1;
	if (mdb_env_set_maxdbs(services_db_env, 5) != 0) // nick->account + cert->account + account->nicks (also used for account list) + account->certs + account->name
		return 1;
	for (size_t i = 0; i < SERVICES_DB_PATH.len; i++) {
		if (SERVICES_DB_PATH.data[i] == 0)
			return 1; // LMDB does not support null in the filepath... nor do normal FSes really, but that can be changed
	}
	char path[SERVICES_DB_PATH.len + 1];
	memcpy(path, SERVICES_DB_PATH.data, SERVICES_DB_PATH.len);
	path[SERVICES_DB_PATH.len] = 0;
	if (mdb_env_open(services_db_env, path, MDB_NOSUBDIR | MDB_NOTLS | MDB_NORDAHEAD, 0600) != 0)
		return 1;
	{
		int discard;
		if (mdb_reader_check(services_db_env, &discard) != 0)
			return 1;
	}

	MDB_txn *txn;
	if (mdb_txn_begin(services_db_env, NULL, 0, &txn) != 0)
		return 1;
	if (mdb_dbi_open(txn, "nick_to_account", MDB_CREATE, &services_nick_to_account) != 0) {
		mdb_txn_abort(txn);
		return 1;
	}
	if (mdb_dbi_open(txn, "cert_to_account", MDB_CREATE, &services_cert_to_account) != 0) {
		mdb_txn_abort(txn);
		return 1;
	}
	if (mdb_dbi_open(txn, "account_to_nicks", MDB_CREATE | MDB_DUPSORT, &services_account_to_nicks) != 0) {
		mdb_txn_abort(txn);
		return 1;
	}
	if (mdb_dbi_open(txn, "account_to_certs", MDB_CREATE | MDB_DUPSORT, &services_account_to_certs) != 0) {
		mdb_txn_abort(txn);
		return 1;
	}
	if (mdb_dbi_open(txn, "account_to_name", MDB_CREATE, &services_account_to_name) != 0) {
		mdb_txn_abort(txn);
		return 1;
	}
	if (mdb_txn_commit(txn) != 0)
		return 1;

	pseudoclients[SERVICES_PSEUDOCLIENT].init = services_pseudoclient_init;

	pseudoclients[SERVICES_PSEUDOCLIENT].post_reload = services_pseudoclient_post_reload;
	pseudoclients[SERVICES_PSEUDOCLIENT].pre_reload = services_pseudoclient_pre_reload;

	pseudoclients[SERVICES_PSEUDOCLIENT].allow_kill = services_pseudoclient_allow_kill;
	pseudoclients[SERVICES_PSEUDOCLIENT].allow_kick = services_pseudoclient_allow_kick;

	pseudoclients[SERVICES_PSEUDOCLIENT].handle_privmsg = services_pseudoclient_handle_privmsg;
	pseudoclients[SERVICES_PSEUDOCLIENT].handle_rename_user = services_pseudoclient_handle_rename_user;
	pseudoclients[SERVICES_PSEUDOCLIENT].handle_set_cert = services_pseudoclient_handle_set_cert;

	pseudoclients[SERVICES_PSEUDOCLIENT].handle_post_rename_user = services_pseudoclient_handle_post_rename_user;

	return 0;
}

int services_pseudoclient_pre_reload(void) {
	mdb_env_close(services_db_env);

	return 0;
}

int services_pseudoclient_allow_kill(struct string from, struct string source, struct user_info *user, struct string reason) {
	return 0;
}

int services_pseudoclient_allow_kick(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
	return 0;
}

void services_pseudoclient_handle_privmsg(struct string from, struct string source, struct string target, struct string msg) {
	char exists;
	struct user_info *user = get_table_index(user_list, source, &exists).data;
	if (!exists)
		return;

	if (STRING_EQ(target, NICKSERV_UID)) {
		if (case_string_eq(msg, STRING("REGISTER"))) {
			if (user->cert.len == 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("You must be using a TLS client cert to use this command."));
				return;
			}

			if (user->account_name.len != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("You are already registered."));
				return;
			}
			struct string nick_upper;
			if (str_clone(&nick_upper, user->nick) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Account registration failed (OOM)."));
				return;
			}
			for (size_t i = 0; i < nick_upper.len; i++)
				nick_upper.data[i] = CASEMAP(nick_upper.data[i]);

			MDB_txn *txn;
			if (mdb_txn_begin(services_db_env, NULL, 0, &txn) != 0) {
				free(nick_upper.data);
				notice(SID, NICKSERV_UID, user->uid, STRING("Account registration failed (Probably OOM)."));
				return;
			}

			MDB_val key = {
				.mv_data = nick_upper.data,
				.mv_size = nick_upper.len,
			};
			MDB_val data = key;

			if (mdb_put(txn, services_account_to_nicks, &key, &data, MDB_NOOVERWRITE) != 0) {
				mdb_txn_abort(txn);
				free(nick_upper.data);
				notice(SID, NICKSERV_UID, user->uid, STRING("Account already exists."));
				return;
			}
			if (mdb_put(txn, services_nick_to_account, &key, &data, MDB_NOOVERWRITE) != 0) {
				mdb_txn_abort(txn);
				free(nick_upper.data);
				notice(SID, NICKSERV_UID, user->uid, STRING("Nickname already registered."));
				return;
			}

			data.mv_data = user->cert.data;
			data.mv_size = user->cert.len;
			if (mdb_put(txn, services_account_to_certs, &key, &data, MDB_NOOVERWRITE) != 0) {
				mdb_txn_abort(txn);
				free(nick_upper.data);
				notice(SID, NICKSERV_UID, user->uid, STRING("Account already exists."));
				return;
			}

			data = key;
			key.mv_data = user->cert.data;
			key.mv_size = user->cert.len;
			if (mdb_put(txn, services_cert_to_account, &key, &data, MDB_NOOVERWRITE) != 0) {
				mdb_txn_abort(txn);
				free(nick_upper.data);
				notice(SID, NICKSERV_UID, user->uid, STRING("Cert already in use for another account."));
				return;
			}

			key = data;
			data.mv_data = user->nick.data;
			data.mv_size = user->nick.len;
			if (mdb_put(txn, services_account_to_name, &key, &data, MDB_NOOVERWRITE) != 0) {
				mdb_txn_abort(txn);
				free(nick_upper.data);
				notice(SID, NICKSERV_UID, user->uid, STRING("Account already exists."));
				return;
			}

			if (mdb_txn_commit(txn) != 0) {
				free(nick_upper.data);
				notice(SID, NICKSERV_UID, user->uid, STRING("Account registration failed (Internal error)."));
				return;
			}

			free(nick_upper.data);

			set_account(SID, user, user->nick, NICKSERV_UID);

			notice(SID, NICKSERV_UID, user->uid, STRING("Account registered."));
		} else if (case_string_eq(msg, STRING("GROUP"))) {
			if (user->account_name.len == 0)
				goto group_fail;
			struct string nick_upper;
			if (str_clone(&nick_upper, user->nick) != 0)
				goto group_fail;
			for (size_t i = 0; i < nick_upper.len; i++)
				nick_upper.data[i] = CASEMAP(nick_upper.data[i]);
			struct string account_upper;
			if (str_clone(&account_upper, user->account_name) != 0)
				goto group_fail_free_nick;
			for (size_t i = 0; i < account_upper.len; i++)
				account_upper.data[i] = CASEMAP(account_upper.data[i]);

			MDB_txn *txn;
			if (mdb_txn_begin(services_db_env, NULL, 0, &txn) != 0)
				goto group_fail_free_account;

			MDB_val key = {
				.mv_data = nick_upper.data,
				.mv_size = nick_upper.len,
			};
			MDB_val data = {
				.mv_data = account_upper.data,
				.mv_size = account_upper.len,
			};

			if (mdb_put(txn, services_nick_to_account, &key, &data, MDB_NOOVERWRITE) != 0)
				goto group_fail_abort;

			key = data;
			data.mv_data = nick_upper.data;
			data.mv_size = nick_upper.len;
			if (mdb_put(txn, services_account_to_nicks, &key, &data, 0) != 0) // DUPSORT, lack of conflict was confirmed in the previous one anyways
				goto group_fail_abort;

			if (mdb_txn_commit(txn) != 0)
				goto group_fail_free_account;

			free(nick_upper.data);
			free(account_upper.data);

			notice(SID, NICKSERV_UID, user->uid, STRING("Nickname grouped."));

			return;

			group_fail_abort:
			mdb_txn_abort(txn);
			group_fail_free_account:
			free(account_upper.data);
			group_fail_free_nick:
			free(nick_upper.data);
			group_fail:
			notice(SID, NICKSERV_UID, user->uid, STRING("Unable to group nickname."));
			return;
		} else if (case_string_eq(msg, STRING("UNGROUP"))) {
			if (user->account_name.len == 0)
				goto ungroup_fail;
			struct string nick_upper;
			if (str_clone(&nick_upper, user->nick) != 0)
				goto ungroup_fail;
			for (size_t i = 0; i < nick_upper.len; i++)
				nick_upper.data[i] = CASEMAP(nick_upper.data[i]);
			struct string account_upper;
			if (str_clone(&account_upper, user->account_name) != 0)
				goto ungroup_fail_free_nick;
			for (size_t i = 0; i < account_upper.len; i++)
				account_upper.data[i] = CASEMAP(account_upper.data[i]);

			if (STRING_EQ(account_upper, nick_upper)) {
				notice(SID, NICKSERV_UID, user->uid, STRING("This is your accountname. Please change your account name first. <not yet implemented>"));
				goto ungroup_fail_free_account;
			}

			MDB_txn *txn;
			if (mdb_txn_begin(services_db_env, NULL, 0, &txn) != 0)
				goto ungroup_fail_free_account;

			MDB_val key = {
				.mv_data = nick_upper.data,
				.mv_size = nick_upper.len,
			};

			if (mdb_del(txn, services_nick_to_account, &key, 0) != 0)
				goto ungroup_fail_abort;

			MDB_val data = key;
			key.mv_data = account_upper.data;
			key.mv_size = account_upper.len;

			if (mdb_del(txn, services_account_to_nicks, &key, &data) != 0)
				goto ungroup_fail_abort;

			if (mdb_txn_commit(txn) != 0)
				goto ungroup_fail_free_account;

			notice(SID, NICKSERV_UID, user->uid, STRING("Nickname ungrouped."));

			free(account_upper.data);
			free(nick_upper.data);
			return;

			ungroup_fail_abort:
			mdb_txn_abort(txn);
			ungroup_fail_free_account:
			free(account_upper.data);
			ungroup_fail_free_nick:
			free(nick_upper.data);
			ungroup_fail:
			notice(SID, NICKSERV_UID, user->uid, STRING("Unable to ungroup nickname."));
			return;
		} else if (case_string_eq(msg, STRING("LIST"))) {
			if (user->account_name.len == 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("You are not logged in."));
			} else {
				struct string account_upper;
				if (str_clone(&account_upper, user->account_name) != 0)
					goto group_fail_free_nick;
				for (size_t i = 0; i < account_upper.len; i++)
					account_upper.data[i] = CASEMAP(account_upper.data[i]);

				MDB_txn *txn;
				if (mdb_txn_begin(services_db_env, NULL, MDB_RDONLY, &txn) != 0) {
					free(account_upper.data);
					return;
				}

				MDB_cursor *cursor;
				if (mdb_cursor_open(txn, services_account_to_nicks, &cursor) != 0) {
					free(account_upper.data);
					mdb_txn_abort(txn);
					return;
				}

				MDB_val key = {
					.mv_data = account_upper.data,
					.mv_size = account_upper.len,
				};
				MDB_val data;
				if (mdb_cursor_get(cursor, &key, &data, MDB_SET) != 0) {
					free(account_upper.data);
					mdb_cursor_close(cursor);
					mdb_txn_abort(txn);
					return;
				}

				notice(SID, NICKSERV_UID, user->uid, STRING("Your nicks (case-insensitive, uppercased):"));

				do {
					struct string name = {.data = data.mv_data, .len = data.mv_size};
					notice(SID, NICKSERV_UID, user->uid, name);
				} while (mdb_cursor_get(cursor, &key, &data, MDB_NEXT_DUP) == 0);

				mdb_cursor_close(cursor);
				if (mdb_cursor_open(txn, services_account_to_certs, &cursor) != 0) {
					free(account_upper.data);
					mdb_txn_abort(txn);
					return;
				}

				if (mdb_cursor_get(cursor, &key, &data, MDB_SET) != 0) {
					free(account_upper.data);
					mdb_cursor_close(cursor);
					mdb_txn_abort(txn);
					return;
				}

				notice(SID, NICKSERV_UID, user->uid, STRING("Your certs:"));

				do {
					struct string name = {.data = data.mv_data, .len = data.mv_size};
					notice(SID, NICKSERV_UID, user->uid, name);
				} while (mdb_cursor_get(cursor, &key, &data, MDB_NEXT_DUP) == 0);

				mdb_cursor_close(cursor);
				mdb_txn_abort(txn);

				free(account_upper.data);
			}
		} else if (msg.len >= 8 && case_string_eq((struct string){.data = msg.data, .len = 8}, STRING("ADDCERT "))) {
			if (user->account_name.len == 0)
				goto addcert_fail;

			struct string account_upper;
			if (str_clone(&account_upper, user->account_name) != 0)
				goto addcert_fail;
			for (size_t i = 0; i < account_upper.len; i++)
				account_upper.data[i] = CASEMAP(account_upper.data[i]);

			MDB_txn *txn;
			if (mdb_txn_begin(services_db_env, NULL, 0, &txn) != 0)
				goto addcert_fail_free_account;

			MDB_val key = {
				.mv_data = msg.data + 8,
				.mv_size = msg.len - 8,
			};

			MDB_val data = {
				.mv_data = account_upper.data,
				.mv_size = account_upper.len,
			};

			if (mdb_put(txn, services_cert_to_account, &key, &data, MDB_NOOVERWRITE) != 0)
				goto addcert_fail_abort;

			data = key;
			key.mv_data = account_upper.data;
			key.mv_size = account_upper.len;
			if (mdb_put(txn, services_account_to_certs, &key, &data, 0) != 0)
				goto addcert_fail_abort;

			if (mdb_txn_commit(txn) != 0)
				goto addcert_fail_free_account;

			notice(SID, NICKSERV_UID, user->uid, STRING("Cert added."));

			free(account_upper.data);
			return;

			addcert_fail_abort:
			mdb_txn_abort(txn);
			addcert_fail_free_account:
			free(account_upper.data);
			addcert_fail:
			notice(SID, NICKSERV_UID, user->uid, STRING("Unable to add cert."));
			return;
		} else if (msg.len >= 8 && case_string_eq((struct string){.data = msg.data, .len = 8}, STRING("DELCERT "))) {
			if (user->account_name.len == 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("You're not logged in."));
				goto delcert_fail;
			}

			struct string account_upper;
			if (str_clone(&account_upper, user->account_name) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Unable to remove cert."));
				goto delcert_fail;
			}

			for (size_t i = 0; i < account_upper.len; i++)
				account_upper.data[i] = CASEMAP(account_upper.data[i]);

			MDB_txn *txn;
			if (mdb_txn_begin(services_db_env, NULL, 0, &txn) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Unable to remove cert."));
				goto delcert_fail_free_account;
			}

			MDB_val key = {
				.mv_data = msg.data + 8,
				.mv_size = msg.len - 8,
			};


			if (mdb_del(txn, services_cert_to_account, &key, 0) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Cert removed. (You don't have this cert)"));
				goto delcert_fail_abort;
			}

			MDB_val data = key;
			key.mv_data = account_upper.data;
			key.mv_size = account_upper.len;

			if (mdb_del(txn, services_account_to_certs, &key, &data) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Cert removed. (You don't have this cert)"));
				goto delcert_fail_abort;
			}

			if (mdb_get(txn, services_account_to_certs, &key, &data) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("This is your last cert, you would not be able to log in if this was removed."));
				goto delcert_fail_abort;
			}

			if (mdb_txn_commit(txn) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Unable to remove cert."));
				goto delcert_fail_abort;
			}

			notice(SID, NICKSERV_UID, user->uid, STRING("Cert removed."));

			free(account_upper.data);
			return;

			delcert_fail_abort:
			mdb_txn_abort(txn);
			delcert_fail_free_account:
			free(account_upper.data);
			delcert_fail:
			return;
		} else if (msg.len >= 13 && case_string_eq((struct string){.data = msg.data, .len = 13}, STRING("DROP ACCOUNT "))) {
			struct string required_account_name = {.data = msg.data + 13, .len = msg.len - 13};
			if (user->account_name.len == 0 || !STRING_EQ(required_account_name, user->account_name)) {
				notice(SID, NICKSERV_UID, user->uid, STRING("You must be logged into the account that you wish to drop."));
				goto drop_fail;
			}

			struct string account_upper;
			if (str_clone(&account_upper, user->account_name) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto drop_fail;
			}

			for (size_t i = 0; i < account_upper.len; i++)
				account_upper.data[i] = CASEMAP(account_upper.data[i]);

			MDB_txn *txn;
			if (mdb_txn_begin(services_db_env, NULL, 0, &txn) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto drop_fail_free_account_upper;
			}

			MDB_val acc = {
				.mv_data = account_upper.data,
				.mv_size = account_upper.len,
			};

			MDB_val key;

			MDB_cursor *cursor;
			if (mdb_cursor_open(txn, services_account_to_nicks, &cursor) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto drop_fail_abort;
			}

			int ret = mdb_cursor_get(cursor, &acc, &key, MDB_SET);
			if (ret != 0 && ret != MDB_NOTFOUND) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto drop_fail_close_cursor;
			} else if (ret != MDB_NOTFOUND) {
				do {
					mdb_del(txn, services_nick_to_account, &key, NULL);
				} while (mdb_cursor_get(cursor, &acc, &key, MDB_NEXT_DUP) == 0);
			}
			mdb_cursor_close(cursor);

			mdb_del(txn, services_account_to_nicks, &acc, NULL);

			if (mdb_cursor_open(txn, services_account_to_certs, &cursor) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto drop_fail_abort;
			}

			ret = mdb_cursor_get(cursor, &acc, &key, MDB_SET);
			if (ret != 0 && ret != MDB_NOTFOUND) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto drop_fail_close_cursor;
			} else if (ret != MDB_NOTFOUND) {
				do {
					mdb_del(txn, services_cert_to_account, &key, NULL);
				} while (mdb_cursor_get(cursor, &acc, &key, MDB_NEXT_DUP) == 0);
			}
			mdb_cursor_close(cursor);

			mdb_del(txn, services_account_to_certs, &acc, NULL);

			mdb_del(txn, services_account_to_name, &acc, NULL);

			if (mdb_txn_commit(txn) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto drop_fail_free_account_upper;
			}
			free(account_upper.data);

			for (size_t i = 0; i < user_list.len; i++) {
				struct user_info *user = user_list.array[i].ptr.data;
				if (STRING_EQ(user->account_name, required_account_name)) {
					if (set_account(SID, user, STRING(""), NICKSERV_UID) != 0) {
						kill_user(SID, NICKSERV_UID, user, STRING("Killed: Internal error attempting to log out on account removal. Forcing logout the hard way.")); // TODO: Make it so this really can't happen
					}
				}
			}

			notice(SID, NICKSERV_UID, user->uid, STRING("Account removed."));
			return;

			drop_fail_close_cursor:
			mdb_cursor_close(cursor);
			drop_fail_abort:
			mdb_txn_abort(txn);
			drop_fail_free_account_upper:
			free(account_upper.data);
			drop_fail:
			return;
		} else if (case_string_eq(msg, STRING("LOGIN"))) {
			MDB_txn *txn;
			if (mdb_txn_begin(services_db_env, NULL, MDB_RDONLY, &txn) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				return;
			}

			MDB_val key = {
				.mv_data = user->cert.data,
				.mv_size = user->cert.len,
			};
			MDB_val data;

			if (mdb_get(txn, services_cert_to_account, &key, &data) != 0) {
				mdb_txn_abort(txn);
				notice(SID, NICKSERV_UID, user->uid, STRING("Nothing to log you in to."));
				return;
			}
			key = data;
			if (mdb_get(txn, services_account_to_name, &key, &data) != 0) {
				mdb_txn_abort(txn);
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				return;
			}
			struct string account = {.data = data.mv_data, .len = data.mv_size};
			set_account(SID, user, account, NICKSERV_UID);
			mdb_txn_abort(txn);
			notice(SID, NICKSERV_UID, user->uid, STRING("Login successful."));
		} else if (case_string_eq(msg, STRING("FIX"))) {
			if (user->account_name.len == 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("You're not logged in, so there's no account to fix."));
				goto fix_fail;
			}

			struct string account_upper;
			if (str_clone(&account_upper, user->account_name) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto fix_fail;
			}

			for (size_t i = 0; i < account_upper.len; i++)
				account_upper.data[i] = CASEMAP(account_upper.data[i]);

			MDB_txn *txn;
			if (mdb_txn_begin(services_db_env, NULL, 0, &txn) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto fix_fail_free_account;
			}

			MDB_val key = {
				.mv_data = account_upper.data,
				.mv_size = account_upper.len,
			};

			MDB_val data = {
				.mv_data = user->account_name.data,
				.mv_size = user->account_name.len,
			};

			mdb_put(txn, services_account_to_name, &key, &data, MDB_NOOVERWRITE);

			if (mdb_get(txn, services_nick_to_account, &key, &data) == 0) {
				struct string other_name = {.data = data.mv_data, .len = data.mv_size};
				if (!STRING_EQ(other_name, account_upper)) {
					notice(SID, NICKSERV_UID, user->uid, STRING("This name belongs to another account."));
					goto fix_fail_abort;
				}
			}

			data = key;
			mdb_put(txn, services_account_to_nicks, &key, &data, 0);
			mdb_put(txn, services_nick_to_account, &key, &data, MDB_NOOVERWRITE);

			MDB_cursor *cursor;
			if (mdb_cursor_open(txn, services_account_to_nicks, &cursor) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto fix_fail_abort;
			}

			if (mdb_cursor_get(cursor, &key, &data, MDB_SET) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto fix_fail_close_cursor;
			}

			do {
				struct string name = {.data = data.mv_data, .len = data.mv_size};
				for (size_t i = 0; i < name.len; i++) {
					if (CASEMAP(name.data[i]) != name.data[i]) {
						mdb_cursor_del(cursor, 0);
						mdb_del(txn, services_nick_to_account, &data, &key);
						break;
					}
				}
			} while (mdb_cursor_get(cursor, &key, &data, MDB_NEXT_DUP) == 0);

			if (mdb_txn_commit(txn) != 0) {
				notice(SID, NICKSERV_UID, user->uid, STRING("Internal error."));
				goto fix_fail_free_account;
			}
			free(account_upper.data);

			notice(SID, NICKSERV_UID, user->uid, STRING("Account fixed."));
			return;

			fix_fail_close_cursor:
			mdb_cursor_close(cursor);
			fix_fail_abort:
			mdb_txn_abort(txn);
			fix_fail_free_account:
			free(account_upper.data);
			fix_fail:
			return;
		} else {
			notice(SID, NICKSERV_UID, user->uid, STRING("Supported commands:"));
			notice(SID, NICKSERV_UID, user->uid, STRING("        HELP     lists commands."));
			notice(SID, NICKSERV_UID, user->uid, STRING("        REGISTER registers your current nick to your current TLS client cert."));
			notice(SID, NICKSERV_UID, user->uid, STRING("        GROUP    adds your current nick to your account."));
			notice(SID, NICKSERV_UID, user->uid, STRING("        UNGROUP  removes your current nick from your account."));
			notice(SID, NICKSERV_UID, user->uid, STRING("        ADDCERT  adds a specified cert to your account."));
			notice(SID, NICKSERV_UID, user->uid, STRING("        DELCERT  removes a specified cert from your account."));
			notice(SID, NICKSERV_UID, user->uid, STRING("        LIST     lists nicks and certs associated with your account."));
			notice(SID, NICKSERV_UID, user->uid, STRING("        LOGIN    triggers automatic login behavior."));
			notice(SID, NICKSERV_UID, user->uid, STRING("        FIX      fixes your account (temporary measure)."));
			notice(SID, NICKSERV_UID, user->uid, STRING("        DROP ACCOUNT <account name>. Deletes your account."));
		}
	}

	return;
}

void services_pseudoclient_handle_rename_user(struct string from, struct user_info *user, struct string nick, size_t timestamp, char forced, char immediate) {
	return;
}

void services_pseudoclient_handle_post_rename_user(struct string from, struct user_info *user, struct string nick, size_t old_timestamp, char forced, char immediate) {
	if (forced)
		return;

	struct string nick_upper;
	if (str_clone(&nick_upper, nick) != 0)
		return;
	for (size_t i = 0; i < nick_upper.len; i++)
		nick_upper.data[i] = CASEMAP(nick_upper.data[i]);

	MDB_val key = {
		.mv_data = nick_upper.data,
		.mv_size = nick_upper.len,
	};
	MDB_val data;

	MDB_txn *txn;
	if (mdb_txn_begin(services_db_env, NULL, MDB_RDONLY, &txn) != 0) {
		free(nick_upper.data);
		return;
	}

	if (mdb_get(txn, services_nick_to_account, &key, &data) != 0) {
		free(nick_upper.data);
		mdb_txn_abort(txn);
		return;
	}
	free(nick_upper.data);

	key = data;
	if (mdb_get(txn, services_account_to_name, &key, &data) != 0) {
		mdb_txn_abort(txn);
		return;
	}

	struct string required_account_name = {.data = data.mv_data, .len = data.mv_size};
	if (!STRING_EQ(required_account_name, user->account_name)) {
		rename_user(SID, user, user->uid, 100, 1, 1);
		notice(SID, NICKSERV_UID, user->uid, STRING("Nickname change forced due to attempting to use a nick registered to a different account."));
	}

	mdb_txn_abort(txn);

	return;
}

void services_pseudoclient_handle_set_cert(struct string from, struct user_info *user, struct string cert, struct string source) {
	if (cert.len != 0)
	do {
		MDB_txn *txn;
		if (mdb_txn_begin(services_db_env, NULL, MDB_RDONLY, &txn) != 0) {
			break;
		}

		MDB_val key = {
			.mv_data = cert.data,
			.mv_size = cert.len,
		};
		MDB_val data;

		if (mdb_get(txn, services_cert_to_account, &key, &data) != 0) {
			mdb_txn_abort(txn);
			break;
		}
		key = data;
		if (mdb_get(txn, services_account_to_name, &key, &data) != 0) {
			mdb_txn_abort(txn);
			break;
		}
		struct string account = {.data = data.mv_data, .len = data.mv_size};
		set_account(SID, user, account, NICKSERV_UID);
		mdb_txn_abort(txn);
	} while (0);

	struct string nick_upper;
	if (str_clone(&nick_upper, user->nick) != 0)
		return;
	for (size_t i = 0; i < nick_upper.len; i++)
		nick_upper.data[i] = CASEMAP(nick_upper.data[i]);

	MDB_val key = {
		.mv_data = nick_upper.data,
		.mv_size = nick_upper.len,
	};
	MDB_val data;

	MDB_txn *txn;
	if (mdb_txn_begin(services_db_env, NULL, MDB_RDONLY, &txn) != 0) {
		free(nick_upper.data);
		return;
	}

	if (mdb_get(txn, services_nick_to_account, &key, &data) != 0) {
		free(nick_upper.data);
		mdb_txn_abort(txn);
		return;
	}
	free(nick_upper.data);

	key = data;
	if (mdb_get(txn, services_account_to_name, &key, &data) != 0) {
		mdb_txn_abort(txn);
		return;
	}

	struct string required_account_name = {.data = data.mv_data, .len = data.mv_size};
	if (!STRING_EQ(required_account_name, user->account_name)) {
		rename_user(SID, user, user->uid, 100, 1, 1);
		notice(SID, NICKSERV_UID, user->uid, STRING("Nickname change forced due to attempting to use a nick registered to a different account."));
	}

	mdb_txn_abort(txn);

	return;
}
