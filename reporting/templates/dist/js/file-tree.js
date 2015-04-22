'use strict';

(function($){

    $.fn.fileTree = function(options){

        var defaults = {
            data: undefined,
            sortable: false,
            selectable: false
        };

        function initTreeBuilder(elements){
            options = $.extend(defaults, options);

            return elements.each(function() {
                var o = options;
                var obj = $(this);
                var list = '<ol class="tree">';

                o.data.forEach(function(rootItem){
                    if(rootItem.type === 'dir'){
                        list = list + _renderDir(rootItem);
                    }else{
                        list = list + _renderFile(rootItem);
                    }
                });

                list = list + '</ol>';
                obj.append(list);
                obj.addClass('file-tree');

                // Initial state
                obj.find('li.folder').addClass('mjs-nestedSortable-collapsed');

                // Add listeners
                _bindListeners(obj);

                if(options.sortable){
                    // Sortable
                    _initSortable(obj);
                }else if(options.selectable){
                    // Selectable
                    _initSelectable(obj);
                }
            });
        }
        function toObject(element){
            function serializeBranches(el){
                var serializedObj = [];

                $(el).children('ol').children('li').each(function(){
                    var serializedObjBranch = {};

                    serializedObjBranch.id = $(this).data('id');
                    serializedObjBranch.name = $(this).data('name');
                    serializedObjBranch.type = $(this).data('type');

                    if($(this).children('ol').children('li').length > 0){
                        serializedObjBranch.children = serializeBranches($(this));
                    }
                    serializedObj.push(serializedObjBranch);
                });
                return serializedObj;
            }
            return serializeBranches(element);
        }
        function toJson(element){
            return JSON.stringify(toObject(element));
        }

        function _bindListeners(obj){
            $(obj).find('.tree li.folder > div').on('click', function() {
                $(this).closest('li').toggleClass('mjs-nestedSortable-collapsed').toggleClass('mjs-nestedSortable-expanded');
            });
        }
        function _initSortable(obj){
            obj.addClass('sortable');

            // Initiate nestedSortable plugin
            $(obj).find('> ol.tree').nestedSortable({
                forcePlaceholderSize: true,
                handle: 'span',
                helper:	'clone',
                items: 'li',
                opacity: 0.6,
                placeholder: 'placeholder',
                revert: 250,
                tabSize: 20,
                tolerance: 'pointer',
                toleranceElement: '> div',
                maxLevels: 0,

                isTree: true,
                expandOnHover: 400,
                startCollapsed: true
            });
        }
        function _initSelectable(obj){
            obj.addClass('selectable');

            $(obj).find('.tree li.folder > div').on('click', function(e){ _selectItem($(this).parent()); e.stopPropagation(); });
            $(obj).find('.tree li.file > div').on('click', function(e){ _selectItem($(this).parent()); e.stopPropagation(); });

            function _selectItem(item){
                $(obj).find('.tree li.folder').removeClass('selected');
                $(obj).find('.tree li.file').removeClass('selected');

                $(item).addClass('selected');
                $(obj).trigger('itemSelected', [item]);
            }
        }
        function _loopChildren(parent){

            var list = '';
            parent.children.forEach(function(child){
                if(child.type === 'dir'){
                    list = list + _renderDir(child);
                }else{
                    list = list + _renderFile(child);
                }
            });
            return list;
        }
        function _renderFile(file){
            var listItem = '';

            if(file.id !== undefined){
                listItem = '<li class="file mjs-nestedSortable-no-nesting" data-id="' + file.id + '" data-type="file" data-name="' + file.name + '"><div>';
            }else{
                listItem = '<li class="file mjs-nestedSortable-no-nesting"><div>';
            }

            if(file.url !== undefined && options.selectable !== true){
                listItem = listItem + '<a href="' + file.url + '"><span></span>' + file.name + '</a></div></li>';
            }else{
                listItem = listItem + '<span></span>' + file.name + '</div></li>';
            }

            return listItem;
        }
        function _renderDir(dir){
            var listItem;

            if(dir.id !== undefined){
                listItem = '<li class="folder" data-id="' + dir.id + '" data-type="folder" data-name="' + dir.name + '" ><div><span></span>' + dir.name + '</div>';
            }else{
                listItem = '<li class="folder"><div><span></span>' + dir.name + '</div>';
            }

            if(dir.children !== undefined){
                listItem = listItem + '<ol>' + _loopChildren(dir) + '</ol>';
            }

            listItem = listItem + '</li>';

            return listItem;
        }

        switch (options){
            case 'toObject':
                return toObject(this);
            case 'toJson':
                return toJson(this);
            default:
                return initTreeBuilder(this);
        }

    };

}(jQuery));