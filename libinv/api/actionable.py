from flask import Blueprint
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from libinv.base import engine
from libinv.models import Repository
from libinv.scio_models import VulnerablePath

actionable = Blueprint("actionable", __name__, template_folder="templates")


def fetch_repository(repository_id):
    try:
        Session = sessionmaker(bind=engine)
        conn = Session()
        result = conn.query(Repository).filter_by(id=repository_id).first()
        return result
    except SQLAlchemyError as e:
        conn.rollback()
        print(str(e))
    finally:
        conn.close()


def fetch_vulnerable_packages(repository_id, environment):
    try:
        Session = sessionmaker(bind=engine)
        conn = Session()
        vulnerable_package_ids = conn.execute(
            text(
                "SELECT DISTINCT vulnerable_package_id FROM public.scanpipe_vulnerablepaths WHERE "
                + "repository_id = :repository_id AND environment = :environment "
                + "AND has_commons_in_path = false"
            ),
            {"repository_id": repository_id, "environment": environment},
        ).fetchall()
        return [package_id[0] for package_id in vulnerable_package_ids]
    except SQLAlchemyError as e:
        print(e)
        conn.rollback()
    finally:
        conn.close()


def resolve_packages(package_ids):
    try:
        Session = sessionmaker(bind=engine)
        conn = Session()
        packages = conn.execute(
            text(
                "SELECT id,CONCAT('pkg:',type,'/',namespace,'/',name,'@', version,'?',qualifiers)"
                + '  as "purl" FROM public.scanpipe_discoveredpackage WHERE id IN :ids'
            ),
            {"ids": tuple(package_ids)},
        ).fetchall()
        return packages
    except SQLAlchemyError as e:
        conn.rollback()
        print(str(e))
        return []
    finally:
        conn.close()


def fetch_vulnerable_paths(repository_id, environment, allow_commons=False, selected_package=None):
    try:
        Session = sessionmaker(bind=engine)
        conn = Session()
        if selected_package:
            selected_package = int(selected_package)
            vulnerable_paths = (
                conn.query(VulnerablePath)
                .filter_by(
                    repository_id=repository_id,
                    has_commons_in_path=allow_commons,
                    environment=environment,
                    vulnerable_package_id=selected_package,
                )
                .filter(VulnerablePath.action_item.isnot(None))
                .all()
            )
        else:
            vulnerable_paths = (
                conn.query(VulnerablePath)
                .filter_by(
                    repository_id=repository_id,
                    has_commons_in_path=allow_commons,
                    environment=environment,
                )
                .all()
            )
        return vulnerable_paths
    except SQLAlchemyError as e:
        conn.rollback()
        print(str(e))
    finally:
        conn.close()


def resolve_paths(paths):
    # resolve required purls using scancode DB
    package_ids_to_resolve = set()
    for path in paths:
        path = path.path[1:]
        for element in path:
            if element.isdigit():
                package_ids_to_resolve.add(int(element))

    resolved_purls = resolve_packages(package_ids_to_resolve)

    # replace every package id with the resolved purl
    resolved_paths = []
    for path in paths:
        path = path.path
        for i in range(1, len(path)):
            if not path[i].isdigit():
                continue
            for resolved_purl in resolved_purls:
                if int(path[i]) == resolved_purl[0]:
                    path[i] = resolved_purl[1]
                    break
        resolved_paths.append(path)

    return resolved_paths


def extract_actionables(vulnerable_paths):
    """
    Given a vulnerable path, we extract the actionable item from the path
    action_item field has the index of the action item in the path
    """
    resolved_actionables = set()
    for path in vulnerable_paths:
        actionable = path.path[int(path.action_item)]
        resolved_actionables.add(actionable)
    return resolved_actionables


def fetch_actionable_packages(repository_id, environment):
    try:
        Session = sessionmaker(bind=engine)
        conn = Session()
        actionable_packages = conn.execute(
            text(
                """
                    with action_items as (
                        select 
                            replace((path -> action_item::integer)::varchar, '"', '') 
                            "action_item_id"
                        from
                            scanpipe_vulnerablepaths sv 	
                        where 
                            repository_id = :repository_id 
                            and environment = :environment
                            and has_commons_in_path = false
                        group by action_item_id
                    ), 
                    integer_action_items as (
                        select 
                            concat('pkg:', sd.type, '/', sd.namespace, '/', sd.name, '@', sd.version, '?', sd.qualifiers) "action_item_purl"
                        from 
                            action_items
                        left join 
                            scanpipe_discoveredpackage sd on sd.id = action_item_id::integer
                        where  
                            action_item_id::varchar ~ '^[0-9]+$'
                    ), 
                    non_integer_action_items as (
                        select 
                            action_item_id "action_item_purl"
                        from 
                            action_items 
                        where 
                            action_item_id::varchar !~ '^[0-9]+$'
                    )
                    select 
                        * 
                    from 
                        integer_action_items
                    union select * from non_integer_action_items
                """
            ),
            {"repository_id": repository_id, "environment": environment},
        ).fetchall()
        return [package[0] for package in actionable_packages]
    except SQLAlchemyError as e:
        print(e)
        conn.rollback()
    finally:
        conn.close()
    return None


def fetch_available_envs(repository_id):
    Session = sessionmaker(bind=engine)
    conn = Session()
    return (
        conn.query(VulnerablePath)
        .filter_by(repository_id=repository_id)
        .distinct(VulnerablePath.environment)
        .all()
    )


@actionable.route("/", methods=["GET"])
def plain_actionables():
    repository_id = request.args.get("repository_id")
    environment = request.args.get("env", "prod")

    if not repository_id or not environment:
        return jsonify({"error": "repository_id or env parameter missing"}), 500

    repository = fetch_repository(repository_id)
    vulnerable_packages = resolve_packages(fetch_vulnerable_packages(repository_id, environment))

    if len(vulnerable_packages) == 0:
        return render_template(
            "actionables_dashboard.html",
            repository=repository,
            vulnerable_packages=vulnerable_packages,
            selected_env=environment,
            no_actionables=True,
        )

    actionables = fetch_actionable_packages(repository_id, environment)
    return render_template(
        "actionables_dashboard.html",
        actionables=actionables,
        vulnerable_packages=vulnerable_packages,
        repository=repository,
        selected_env=environment,
    )


@actionable.route("/fix", methods=["GET"])
def how_to_fix():
    repository_id = request.args.get("repository_id")
    selected_package = request.args.get("vulnerable_package")
    show_paths = request.args.get("show_paths", False)
    environment = request.args.get("env", "prod")
    if repository_id is not None and selected_package is not None:
        if selected_package == "not-selected":
            return redirect(
                url_for(
                    "actionable.plain_actionables", repository_id=repository_id, env=environment
                )
            )
        available_envs = fetch_available_envs(repository_id)
        selected_package = int(selected_package)
        repository = fetch_repository(repository_id)
        all_vulnerable_packages = resolve_packages(
            fetch_vulnerable_packages(repository_id, environment=environment)
        )
        unresolved_non_commons_paths = fetch_vulnerable_paths(
            repository_id, selected_package=selected_package, environment=environment
        )
        non_commons_paths = resolve_paths(unresolved_non_commons_paths)
        resolved_actionables = extract_actionables(unresolved_non_commons_paths)
        resolved_selected_package = resolve_packages([selected_package])[0]

        if show_paths == "true":
            return render_template(
                "actionables_dashboard.html",
                list_of_actionables=resolved_actionables,
                selected_package_purl=resolved_selected_package,
                selected_package=selected_package,
                repository=repository,
                actionables=resolved_actionables,
                non_commons_paths=non_commons_paths,
                vulnerable_packages=all_vulnerable_packages,
                environments=available_envs,
            )
        else:
            return render_template(
                "actionables_dashboard.html",
                list_of_actionables=resolved_actionables,
                selected_package_purl=resolved_selected_package,
                selected_package=selected_package,
                repository=repository,
                actionables=resolved_actionables,
                vulnerable_packages=all_vulnerable_packages,
                selected_env=environment,
            )
    else:
        return jsonify({"error": "repository_id parameter missing"}), 200
