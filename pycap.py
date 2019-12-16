import dpkt, socket, sys, geoip2.database, datetime
from tkinter import *
from dpkt.compat import compat_ord

global tracker
tracker = []

class pycap():
	def __init__(self, capture, db_path, filter, initialize_window, all_data):
		self.capture = capture
		self.db_path = db_path
		self.filter = filter
		self.initialize_window = initialize_window
		self.all_data = all_data

		self.init_window(capture, db_path, filter)
	
	def init_window(self, capture, db_path, filter):
		global root
		if self.initialize_window == False:
			self.initialize_window = True
			root = Tk()
			root.geometry("1000x500")
			root.title("pycap")
			val = StringVar() # value of entry is stored here
			
			status_bar = "NO.          SOURCE                      DESTINATION                      LOCATION (src)                                 LOCATION (dst)                                PROTOCOL"
			status = Label(root, text = status_bar, bd = 1, relief = FLAT, anchor = W)
			status.pack(side = TOP, fill = X)
			
			# /\ search frame /\
			search_frame = Frame(root, relief = FLAT)
			search_frame.pack(side = BOTTOM, fill = X)

			info_txt = ("  {}").format(sys.argv[1])
			info = Label(search_frame, text = info_txt)
			info.pack(side = RIGHT)

			label_entry = Label(search_frame, text = "FILTER:   ")
			label_entry.pack(side = LEFT)

			global filter_entry
			filter_entry = Entry(search_frame, textvariable = val, width = 30)
			filter_entry.pack(side = LEFT)
			filter_entry.bind("<Return>", self.apply_filter)
			
			# /\ search frame /\

			scroll = Scrollbar(root)
			scroll.pack(side = RIGHT, fill = Y)
			
			global listbox
			listbox = Listbox(root, yscrollcommand = scroll.set)
			listbox.bind('<Double-Button>', self.more_info)
			listbox.pack(expand = True, side = "left", fill = "both")
			scroll.config(command = listbox.yview)
		
		else: pass
		f = open(capture)
		pcap = dpkt.pcap.Reader(f)
		for line in self.pcap_reader(pcap, filter, 100): listbox.insert(END, line)

		root.mainloop()
	
	def pcap_reader(self, cap, filter, line):
		arr = []

		this_ip = socket.gethostbyname(socket.gethostname())

		for (ts, buf) in cap:
			this_dict = {}
			try:
				eth = dpkt.ethernet.Ethernet(buf)
				ip = eth.data
				src = socket.inet_ntoa(ip.src)
				dst = socket.inet_ntoa(ip.dst)
				protocol = ip.get_proto(ip.p).__name__

				src_copy = src
				dst_copy = dst
				src_lookup = self.ip_lookup(src)
				dst_lookup = self.ip_lookup(dst)
				src_loc_copy = src_lookup
				dst_loc_copy = dst_lookup
				
				do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
				more_fragments = bool(ip.off & dpkt.ip.IP_MF)
				
				if src_copy == this_ip: 
					src_lookup = "[YOU]             "
					src_loc_copy = "[YOU]"
				
				elif dst_copy == this_ip:
					dst_lookup = "[YOU]             "
					dst_loc_copy = "[YOU]"

				this_dict["no"] = str(line)
				this_dict["src"] = src_copy
				this_dict["dst"] = dst_copy
				this_dict["src_lookup"] = src_loc_copy
				this_dict["dst_lookup"] = dst_loc_copy
				this_dict["protocol"] = protocol
				this_dict["ts"] = str(datetime.datetime.utcfromtimestamp(ts))
				this_dict["ttl"] = str(ip.ttl)
				this_dict["df"] = do_not_fragment
				this_dict["mf"] = more_fragments
				this_dict["sport"] = str(ip.data.sport)
				this_dict["dport"] = str(ip.data.dport)

				tcp = ip.data
				if tcp.dport == 80 and len(tcp.data) > 0:
					http = dpkt.http.Request(tcp.data)
					this_dict["http_uri"] = http.uri
					this_dict["user_agent"] = http.headers['user-agent']
					this_dict["http_method"] = http.method
				
				self.all_data.append(this_dict)

				if(len(src) < 13):
					loops = 13 - len(src)
					for i in range(loops): src += "  "
				
				if(len(dst) < 13):
					loops = 13 - len(dst)
					for i in range(loops): dst += "  "
				
				if(len(src_lookup) < 10):
					loops = 9 - len(src_lookup)
					for i in range(loops): src_lookup += "  "
				
				if(len(dst_lookup) < 9):
					loops = 9 - len(dst_lookup)
					for i in range(loops): dst_lookup += "  "
				data_line = ""
				data_line = ("{}.       {}           {}                         {}                                       {}                                  {}").format(line, src, dst, src_lookup, dst_lookup, protocol)

				if len(filter) == 0:
					
					arr.append(data_line)
					line +=1
				
				else:
					for f in filter:
						fv2 = f.split("=")
						target = fv2[0]
						val = fv2[1]
						if target == "no" and int(val) == line:
							
							arr.append(data_line)
							line +=1
							break
						elif target == "src" and val == src_copy:
							
							arr.append(data_line)
							line +=1
							break
						elif target == "dst" and val == dst_copy:
							
							arr.append(data_line)
							line +=1
							break
						elif target == "src_loc" and val == src_loc_copy:
							
							arr.append(data_line)
							line +=1
							break
						elif target == "dst_loc" and val == dst_loc_copy:
							
							arr.append(data_line)
							line +=1
							break
						elif target == "proto" and val == protocol:
							
							arr.append(data_line)
							line +=1
							break
						line += 1
							

			except: continue
		
		return arr
	
	def apply_filter(self, filter):
		global command
		command = (filter_entry.get()).split(",")
		command_list = ["no","src","dst","src_loc","dst_loc","proto"]

		for filter in command:
			fil = filter.split("=")
			target = fil[0]
			
			if target not in command_list: command.remove(filter)
		
		listbox.delete(0, END)
		self.init_window(self.capture, self.db_path, command)
		
	def ip_lookup(self, ip):
		
		try:
			db = geoip2.database.Reader(self.db_path)
			db_response = db.city(ip)
			country = db_response.country.iso_code
			city = db_response.city.name
			identity = "[" + city + "]"
			db.close()
			return identity

		except: return "[Unknown]"

	def more_info(self, val):
		try:
			selection = listbox.curselection()
			pos = str(list(selection)[0] + 100)
			title = ("packet number " + str(pos))

			if pos not in tracker:
				win = Toplevel()
				tracker.append(pos)
				info = []

				for dict in self.all_data:
					if dict.get("no") == pos:
						info.append(dict.get("ts"))
						info.append(dict.get("ttl"))
						info.append(dict.get("df"))
						info.append(dict.get("mf"))
						info.append(dict.get("sport"))
						info.append(dict.get("dport"))
						try:
							info.append(dict.get("http_uri"))
							info.append(dict.get("user_method"))
							info.append(dict.get("http_method"))
						except: pass

						break
					
					else:
						continue
				more_info = new_window(win, title, "400x500", pos, info)

		except: pass
	

class new_window(pycap):
	def __init__(self, master, title, geometry, pos, info):
		self.master = master
		self.title = title
		self.geometry = geometry
		self.pos = pos
		self.info = info

		self.master.title(self.title)
		self.master.geometry(self.geometry)
		self.master.resizable(width = False, height = False)
		self.master.protocol("WM_DELETE_WINDOW",  self.__close__)

		self.display_info()

		self.master.mainloop()

	def __close__(self):
		tracker.remove(self.pos)
		self.master.destroy()
	
	def display_info(self):
		ts_label = Label(self.master, text = ("Timestamp: " + str(self.info[0])))
		ts_label.place(x = 15, y = 20)

		ttl_label = Label(self.master, text = ("Time to live: " + str(self.info[1])))
		ttl_label.place(x = 15, y = 45)

		df_label = Label(self.master, text = ("DF flag: " + str(self.info[2])))
		df_label.place(x = 15, y = 70)

		mf_label =  Label(self.master, text = ("MF flag: " + str(self.info[3])))
		mf_label.place(x = 15, y = 95)

		sport_label =  Label(self.master, text = ("Source port: " + str(self.info[4])))
		sport_label.place(x = 15, y = 120)

		mf_label =  Label(self.master, text = ("Destination port: " + str(self.info[5])))
		mf_label.place(x = 15, y = 145)

		if self.info[5] == "80":
			http_title = Label(self.master, text = "HTTP:")
			http_title.place(x = 15, y = 200)

			method_label = Label(self.master, text = ("- Method: " + str(self.info[8])))
			method_label.place(x = 30, y = 225)

			agent_label = Label(self.master, text = ("- User agent: " + str(self.info[7])))
			agent_label.place(x = 30, y = 250)

			uri_label = Label(self.master, text = ("- URI: " + str(self.info[6])))
			uri_label.place(x = 30, y = 275)

def main(filter):
	db_path = "/opt/geolite-2/GeoLite2-City.mmdb"
	filter = ""
	try:
		pycap_obj = pycap(sys.argv[1], db_path, filter, False, [])

	except Exception as err:
		print("[+] {}").format(err)
		sys.exit()

if __name__ == "__main__":
	main(filter)
