/*
Returns a list of all users with access to the given table and the permissions that grant them access.

Parameters:
-----------
schema : str
    The schema associated with the table you are querying (eg, 'M_HRDW1', 'M_SRDW1')
table_name: str
    The table name you are trying to querying (eg, 'JOB', 'ACAD_PROG')
*/

with table_grants as (
  select
    grantee,
    owner,
    table_name
  from dba_tab_privs
  where
    owner = :schema and
    table_name = :table_name
),

permissions as (
  select
    grantee,
    granted_role,
    substr(sys_connect_by_path(granted_role, '.'), 2) as path,
    connect_by_root granted_role as root,
    level as depth
  from dba_role_privs
  start with granted_role in (select grantee from table_grants)
  connect by granted_role = prior grantee

  union

  select
    username as grantee,
    username as granted_role,
    username as path,
    username as root,
    1 as depth
  from all_users
  where
    username in (select grantee from table_grants)
),

final as (
  select
    a.grantee as username,
    b.owner,
    b.table_name,
    listagg(distinct b.privilege, ', ') within group (order by b.privilege) as privs,
    listagg(distinct path, ', ') within group (order by a.depth) as roles
  from permissions a
    join dba_tab_privs b on
      a.root = b.grantee and
      b.owner = :schema and
      b.table_name = :table_name
  where
    a.grantee in (select username from all_users)
  group by a.grantee, b.owner, b.table_name
)

select * from final order by username;