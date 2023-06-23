/*
Returns a list of all tables & associated permissions within the database for a given user.

Parameters:
-----------
username : str
    The username to query. Typically this is a uniqname or service account (eg, 'JAMJAM', 'RMTRDA_ACCOUNT', etc.).
*/

with permissions as (
  select
    connect_by_root grantee as root,
    granted_role,
    substr(sys_connect_by_path(granted_role, '.'), 2) as path,
    level as depth
  from dba_role_privs
  start with
    grantee = :username
  connect by grantee = prior granted_role

  union

  select
    username as root,
    username as granted_role,
    username as path,
    1 as depth
  from all_users
  where
    username = :username
),

final as (
  select
    a.root as username,
    b.owner as schema,
    b.table_name,
    listagg(distinct a.path, chr(10)) within group (order by a.path) as roles
  from permissions a
    join dba_tab_privs b on
      a.granted_role = b.grantee
  group by a.root, b.owner, b.table_name
)

select * from final order by username, schema, table_name