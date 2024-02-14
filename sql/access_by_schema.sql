/*
Returns a list of all users with access to a given schema, including the permissions 
that grant access to the schema and all tables exposed by those permissions.

Parameters:
-----------
schema : str
    The name of the database schema to query (eg, 'M_HRDW1').
*/


with permissions as (
  -- recursively traverse permissions from end-users down to table privileges
  select
    connect_by_root p.grantee as username,
    p.grantee,
    p.granted_role,
    regexp_replace(sys_connect_by_path(p.granted_role, ' > '), '^\W+', '') as permission_path,
    t.owner as schema,
    t.table_name
  from dba_role_privs p
    left join dba_tab_privs t on
      p.granted_role = t.grantee and
      t.owner = :schema
  connect by p.grantee = prior p.granted_role
  start with p.grantee in (select username from all_users)

  union all

  -- tables that have been directly granted to end-users
  select
    t.grantee as username,
    t.grantee,
    null as granted_role,
    '[Direct Grant]' as permission_path,
    t.owner as schema,
    t.table_name
  from dba_tab_privs t
    join all_users u on t.grantee = u.username
  where
    t.owner = :schema
)

select
  username,
  listagg(distinct permission_path, chr(10)) within group (order by permission_path) as permissions,
  schema,
  listagg(distinct table_name, ', ') within group (order by table_name) as granted_tables
from permissions s
where
  s.table_name is not null
group by username, schema
order by username
